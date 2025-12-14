/**
 * ZKS Key Worker - Simple HTTP Random Key Generator
 * 
 * Minimal worker that generates and returns random keys via HTTP.
 * No WebSockets, no startup code - just pure request handling.
 */

use worker::*;

const CHUNK_SIZE: usize = 16 * 1024; // 16KB chunks

#[event(fetch)]
async fn main(req: Request, _env: Env, _ctx: Context) -> Result<Response> {
    let url = req.url()?;
    let path = url.path();

    // CORS preflight
    if req.method() == Method::Options {
        let mut headers = Headers::new();
        headers.set("Access-Control-Allow-Origin", "*")?;
        headers.set("Access-Control-Allow-Methods", "GET, OPTIONS")?;
        headers.set("Access-Control-Allow-Headers", "Content-Type")?;
        return Ok(Response::empty()?.with_headers(headers));
    }

    // Route: /key/:count - Generate random key chunks
    if path.starts_with("/key/") {
        let chunk_count_str = path.trim_start_matches("/key/");
        let chunk_count: usize = chunk_count_str.parse().unwrap_or(1).min(8000);
        
        let total_size = chunk_count * CHUNK_SIZE;
        let mut key_data = vec![0u8; total_size];
        
        // Generate random bytes - ONLY called during request handling
        getrandom::getrandom(&mut key_data)
            .map_err(|e| Error::RustError(format!("Random failed: {}", e)))?;
        
        let mut headers = Headers::new();
        headers.set("Content-Type", "application/octet-stream")?;
        headers.set("Access-Control-Allow-Origin", "*")?;
        headers.set("Cache-Control", "no-store")?;
        headers.set("X-Chunk-Count", &chunk_count.to_string())?;
        headers.set("X-Chunk-Size", &CHUNK_SIZE.to_string())?;
        
        return Ok(Response::from_bytes(key_data)?.with_headers(headers));
    }

    // Health check
    if path == "/health" {
        let mut headers = Headers::new();
        headers.set("Access-Control-Allow-Origin", "*")?;
        return Ok(Response::ok("ZKS Key OK")?.with_headers(headers));
    }

    let mut headers = Headers::new();
    headers.set("Access-Control-Allow-Origin", "*")?;
    Ok(Response::error("Not Found", 404)?.with_headers(headers))
}
