/**
 * ZKS Vernam Worker - Split-Key One-Time Pad Generator
 * 
 * Generates cryptographically secure random keys for Vernam cipher.
 * Uses WebSocket streaming for real-time key delivery.
 * 
 * SECURITY: Worker only knows keyB. Client knows keyA.
 * Neither alone can decrypt. Only the recipient with both keys can.
 */

use worker::*;

mod vernam_session;
use vernam_session::VernamSession;

fn cors_headers(resp: Response) -> Response {
    let mut headers = Headers::new();
    let _ = headers.set("Access-Control-Allow-Origin", "*");
    let _ = headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    let _ = headers.set("Access-Control-Allow-Headers", "Content-Type");
    resp.with_headers(headers)
}

#[event(fetch)]
async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();

    let url = req.url()?;
    let path = url.path();

    // Handle CORS preflight
    if req.method() == Method::Options {
        return Ok(cors_headers(Response::empty()?));
    }

    // Route: /ws/key/:session_id - WebSocket for key streaming
    if path.starts_with("/ws/key/") {
        let session_id = path.trim_start_matches("/ws/key/").to_string();
        
        if session_id.is_empty() {
            return Ok(cors_headers(Response::error("Missing session_id", 400)?));
        }

        // Get or create Durable Object for this session
        let namespace = env.durable_object("VERNAM_SESSION")?;
        let id = namespace.id_from_name(&session_id)?;
        let stub = id.get_stub()?;

        // Forward request to Durable Object
        return stub.fetch_with_request(req).await;
    }

    // Route: /health - Health check
    if path == "/health" {
        return Ok(cors_headers(Response::ok("ZKS Vernam OK")?));
    }

    Ok(cors_headers(Response::error("Not Found", 404)?))
}
