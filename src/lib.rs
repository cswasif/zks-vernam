/**
 * ZKS Key Worker - HTTP + WebSocket Random Key Generator
 * 
 * Supports both:
 * - HTTP: /key/:count - For small keys (up to 128MB)
 * - WebSocket: /ws/key/:size - For large keys (streaming, unlimited)
 */

use worker::*;

const CHUNK_SIZE: usize = 16 * 1024; // 16KB chunks

#[event(fetch)]
async fn main(req: Request, _env: Env, ctx: Context) -> Result<Response> {
    let url = req.url()?;
    let path = url.path();

    // CORS preflight
    if req.method() == Method::Options {
        let headers = Headers::new();
        headers.set("Access-Control-Allow-Origin", "*")?;
        headers.set("Access-Control-Allow-Methods", "GET, OPTIONS")?;
        headers.set("Access-Control-Allow-Headers", "Content-Type")?;
        return Ok(Response::empty()?.with_headers(headers));
    }

    // WebSocket route: /ws/key/:size (size in bytes)
    if path.starts_with("/ws/key/") {
        let size_str = path.trim_start_matches("/ws/key/");
        let total_size: usize = size_str.parse().unwrap_or(0);
        
        if total_size == 0 {
            return Response::error("Invalid size", 400);
        }

        // Upgrade to WebSocket
        let pair = WebSocketPair::new()?;
        let server = pair.server;
        let client = pair.client;

        // Accept connection
        server.accept()?;

        // Spawn async task for streaming
        ctx.wait_until(async move {
            stream_random_key(&server, total_size).await;
        });

        // Return WebSocket upgrade response
        Response::from_websocket(client)
    }
    // HTTP route: /key/:count - Generate random key chunks
    else if path.starts_with("/key/") {
        let chunk_count_str = path.trim_start_matches("/key/");
        let chunk_count: usize = chunk_count_str.parse().unwrap_or(1).min(8000);
        
        let total_size = chunk_count * CHUNK_SIZE;
        let mut key_data = vec![0u8; total_size];
        
        // Generate random bytes - ONLY called during request handling
        getrandom::getrandom(&mut key_data)
            .map_err(|e| Error::RustError(format!("Random failed: {}", e)))?;
        
        let headers = Headers::new();
        headers.set("Content-Type", "application/octet-stream")?;
        headers.set("Access-Control-Allow-Origin", "*")?;
        headers.set("Cache-Control", "no-store")?;
        headers.set("X-Chunk-Count", &chunk_count.to_string())?;
        headers.set("X-Chunk-Size", &CHUNK_SIZE.to_string())?;
        
        Ok(Response::from_bytes(key_data)?.with_headers(headers))
    }
    // Health check
    else if path == "/health" {
        let headers = Headers::new();
        headers.set("Access-Control-Allow-Origin", "*")?;
        Ok(Response::ok("ZKS Key OK")?.with_headers(headers))
    }
    else {
        let headers = Headers::new();
        headers.set("Access-Control-Allow-Origin", "*")?;
        Response::error("Not Found", 404)
    }
}

/// Stream random key data over WebSocket in chunks
async fn stream_random_key(ws: &WebSocket, total_size: usize) {
    let chunk_count = (total_size + CHUNK_SIZE - 1) / CHUNK_SIZE;
    let mut remaining = total_size;
    
    for i in 0..chunk_count {
        // Determine this chunk's size
        let this_chunk_size = remaining.min(CHUNK_SIZE);
        
        // Generate random chunk
        let mut chunk = vec![0u8; this_chunk_size];
        if getrandom::getrandom(&mut chunk).is_err() {
            let _ = ws.close(Some(1011), Some("Random generation failed"));
            return;
        }
        
        // Send chunk as binary
        if ws.send_with_bytes(&chunk).is_err() {
            return; // Connection closed
        }
        
        remaining -= this_chunk_size;
    }
    
    // Send completion message
    let _ = ws.send_with_str(&format!("{{\"type\":\"complete\",\"chunks\":{},\"size\":{}}}", chunk_count, total_size));
    let _ = ws.close(Some(1000), Some("Complete"));
}
