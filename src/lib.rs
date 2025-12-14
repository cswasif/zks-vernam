/**
 * ZKS Vernam Worker - Stateless Random Key Generator
 * 
 * Generates cryptographically secure random keys for Vernam cipher.
 * Returns key chunks via HTTP response (no Durable Objects needed).
 * 
 * SECURITY: Worker generates keyB, Client generates keyA.
 * Neither alone can decrypt. Only the recipient with both keys can.
 */

use worker::*;

fn cors_headers(resp: Response) -> Response {
    let mut headers = Headers::new();
    let _ = headers.set("Access-Control-Allow-Origin", "*");
    let _ = headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    let _ = headers.set("Access-Control-Allow-Headers", "Content-Type");
    resp.with_headers(headers)
}

const CHUNK_SIZE: usize = 16 * 1024; // 16KB chunks

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

    // Route: /key/:chunk_count - Generate random key chunks
    if path.starts_with("/key/") {
        let chunk_count_str = path.trim_start_matches("/key/");
        let chunk_count: usize = chunk_count_str.parse().unwrap_or(1);
        
        // Limit to reasonable size (max 1000 chunks = ~16MB)
        let chunk_count = chunk_count.min(1000);
        
        // Generate all key chunks
        let total_size = chunk_count * CHUNK_SIZE;
        let mut key_data = vec![0u8; total_size];
        
        getrandom::getrandom(&mut key_data).map_err(|e| {
            Error::RustError(format!("Random generation failed: {}", e))
        })?;
        
        // Return as binary response
        let resp = Response::from_bytes(key_data)?;
        let mut headers = Headers::new();
        headers.set("Content-Type", "application/octet-stream")?;
        headers.set("Access-Control-Allow-Origin", "*")?;
        headers.set("X-Chunk-Count", &chunk_count.to_string())?;
        headers.set("X-Chunk-Size", &CHUNK_SIZE.to_string())?;
        
        return Ok(resp.with_headers(headers));
    }

    // Route: /health - Health check
    if path == "/health" {
        return Ok(cors_headers(Response::ok("ZKS Vernam OK")?));
    }

    Ok(cors_headers(Response::error("Not Found", 404)?))
}
