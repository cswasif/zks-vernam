/**
 * ZKS Vernam Worker - Stateless WebSocket Key Generator
 * 
 * Streams cryptographically secure random keys via WebSocket.
 * No Durable Objects - fully stateless, unlimited streaming.
 * 
 * SECURITY: Worker generates keyB, Client generates keyA.
 * Neither alone can decrypt.
 */

use worker::*;
use futures_util::StreamExt;

const CHUNK_SIZE: usize = 16 * 1024; // 16KB chunks

fn cors_headers(resp: Response) -> Response {
    let headers = Headers::new();
    let mut resp = resp.with_headers(headers);
    let _ = resp.headers_mut().set("Access-Control-Allow-Origin", "*");
    let _ = resp.headers_mut().set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    let _ = resp.headers_mut().set("Access-Control-Allow-Headers", "Content-Type, Upgrade");
    resp
}

#[event(fetch)]
async fn main(req: Request, _env: Env, _ctx: Context) -> Result<Response> {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();

    let url = req.url()?;
    let path = url.path();

    // Handle CORS preflight
    if req.method() == Method::Options {
        return Ok(cors_headers(Response::empty()?));
    }

    // Route: /ws/key - WebSocket for streaming keys
    if path == "/ws/key" {
        let upgrade = req.headers().get("Upgrade")?;
        
        if upgrade.as_deref() != Some("websocket") {
            return Ok(cors_headers(Response::error("WebSocket required", 400)?));
        }

        // Create WebSocket pair
        let pair = WebSocketPair::new()?;
        let server = pair.server;
        let client = pair.client;

        // Accept the connection
        server.accept()?;

        // Spawn handler for this connection
        wasm_bindgen_futures::spawn_local(async move {
            handle_websocket(server).await;
        });

        return Response::from_websocket(client);
    }

    // Route: /key/:count - HTTP fallback for smaller requests
    if path.starts_with("/key/") {
        let chunk_count_str = path.trim_start_matches("/key/");
        let chunk_count: usize = chunk_count_str.parse().unwrap_or(1).min(1000);
        
        let total_size = chunk_count * CHUNK_SIZE;
        let mut key_data = vec![0u8; total_size];
        
        if getrandom::getrandom(&mut key_data).is_err() {
            return Ok(cors_headers(Response::error("Random generation failed", 500)?));
        }
        
        let resp = Response::from_bytes(key_data)?;
        let headers = Headers::new();
        let mut resp = resp.with_headers(headers);
        let _ = resp.headers_mut().set("Content-Type", "application/octet-stream");
        let _ = resp.headers_mut().set("Access-Control-Allow-Origin", "*");
        
        return Ok(resp);
    }

    // Route: /health
    if path == "/health" {
        return Ok(cors_headers(Response::ok("ZKS Vernam OK")?));
    }

    Ok(cors_headers(Response::error("Not Found", 404)?))
}

async fn handle_websocket(ws: WebSocket) {
    let mut events = ws.events().expect("Failed to get event stream");
    
    while let Some(event) = events.next().await {
        match event {
            Ok(WebsocketEvent::Message(msg)) => {
                if let Some(text) = msg.text() {
                    // Handle ping
                    if text == "ping" {
                        let _ = ws.send_with_str("pong");
                        continue;
                    }
                    
                    // Parse request: {"type":"request_key","count":100}
                    if let Ok(req) = serde_json::from_str::<KeyRequest>(&text) {
                        if req.request_type == "request_key" {
                            send_key_chunks(&ws, req.count).await;
                        }
                    }
                }
            }
            Ok(WebsocketEvent::Close(_)) => {
                return;
            }
            Err(_) => {
                return;
            }
        }
    }
}

async fn send_key_chunks(ws: &WebSocket, count: usize) {
    let count = count.min(100000); // Max 100k chunks = ~1.6GB
    
    for i in 0..count {
        // Generate one chunk at a time
        let mut chunk = [0u8; CHUNK_SIZE];
        if getrandom::getrandom(&mut chunk).is_err() {
            let _ = ws.send_with_str(r#"{"type":"error","message":"Random generation failed"}"#);
            return;
        }
        
        // Send as binary
        let _ = ws.send_with_bytes(&chunk);
        
        // Send progress every 100 chunks
        if i % 100 == 0 || i == count - 1 {
            let progress = format!(r#"{{"type":"progress","current":{},"total":{}}}"#, i + 1, count);
            let _ = ws.send_with_str(&progress);
        }
    }
    
    // Send completion
    let _ = ws.send_with_str(&format!(r#"{{"type":"complete","total":{}}}"#, count));
}

#[derive(serde::Deserialize)]
struct KeyRequest {
    #[serde(rename = "type")]
    request_type: String,
    count: usize,
}
