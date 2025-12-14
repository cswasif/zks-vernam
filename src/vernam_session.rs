/**
 * VernamSession - Durable Object for streaming key generation
 * 
 * One session per file transfer. Generates keyB chunks on-demand.
 * Uses WebSocket hibernation for efficiency.
 * 
 * IMPORTANT: Never stores keys. Pure streaming pipe.
 */

use worker::*;
use serde::{Deserialize, Serialize};

const CHUNK_SIZE: usize = 16 * 1024; // 16KB chunks (matches frontend)

#[derive(Clone, Serialize, Deserialize)]
struct SessionState {
    session_id: String,
    role: String,
    chunks_generated: usize,
}

#[derive(Serialize)]
#[serde(tag = "type")]
enum ServerMessage {
    #[serde(rename = "connected")]
    Connected { session_id: String, role: String },
    #[serde(rename = "key_chunk")]
    KeyChunk { index: usize, data: String },
    #[serde(rename = "session_complete")]
    SessionComplete { total_chunks: usize },
    #[serde(rename = "error")]
    Error { message: String },
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum ClientMessage {
    #[serde(rename = "request_key")]
    RequestKey { chunk_count: usize },
    #[serde(rename = "end_session")]
    EndSession,
}

#[durable_object]
pub struct VernamSession {
    state: State,
    #[allow(dead_code)]
    env: Env,
}

impl DurableObject for VernamSession {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        let upgrade = req.headers().get("Upgrade")?;
        
        if upgrade.as_deref() != Some("websocket") {
            return Response::error("WebSocket required", 400);
        }

        // Parse role from query params
        let url = req.url()?;
        let params: std::collections::HashMap<String, String> = url.query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        
        let role = params.get("role").cloned().unwrap_or_else(|| "sender".to_string());
        let session_id = url.path().split('/').last().unwrap_or("unknown").to_string();

        // Create WebSocket pair
        let pair = WebSocketPair::new()?;
        let server = pair.server;
        let client = pair.client;

        // Accept with hibernation
        self.state.accept_web_socket(&server);

        // Store session state in attachment
        let session_state = SessionState {
            session_id: session_id.clone(),
            role: role.clone(),
            chunks_generated: 0,
        };
        server.serialize_attachment(&session_state)?;

        // Send connected message
        let connected_msg = serde_json::to_string(&ServerMessage::Connected {
            session_id: session_state.session_id.clone(),
            role: role.clone(),
        }).unwrap_or_default();
        let _ = server.send_with_str(&connected_msg);

        console_log!("[VernamSession] {} connected as {}", session_id, role);

        Response::from_websocket(client)
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        if let WebSocketIncomingMessage::String(text) = message {
            // Handle ping/pong
            if text == "ping" {
                let _ = ws.send_with_str("pong");
                return Ok(());
            }

            // Parse client message
            if let Ok(msg) = serde_json::from_str::<ClientMessage>(&text) {
                match msg {
                    ClientMessage::RequestKey { chunk_count } => {
                        self.generate_and_send_keys(&ws, chunk_count);
                    }
                    ClientMessage::EndSession => {
                        let complete_msg = serde_json::to_string(&ServerMessage::SessionComplete {
                            total_chunks: 0,
                        }).unwrap_or_default();
                        let _ = ws.send_with_str(&complete_msg);
                        let _ = ws.close(Some(1000), Some("session_complete"));
                    }
                }
            }
        }
        Ok(())
    }

    async fn websocket_close(
        &self,
        ws: WebSocket,
        _code: usize,
        _reason: String,
        _was_clean: bool,
    ) -> Result<()> {
        if let Ok(Some(session)) = ws.deserialize_attachment::<SessionState>() {
            console_log!("[VernamSession] {} disconnected", session.session_id);
        }
        Ok(())
    }

    async fn websocket_error(
        &self,
        _ws: WebSocket,
        error: Error,
    ) -> Result<()> {
        console_error!("[VernamSession] WebSocket error: {:?}", error);
        Ok(())
    }
}

impl VernamSession {
    /// Generate random key chunks and stream them to client
    fn generate_and_send_keys(&self, ws: &WebSocket, chunk_count: usize) {
        console_log!("[VernamSession] Generating {} key chunks", chunk_count);

        for i in 0..chunk_count {
            // Generate cryptographically secure random bytes
            let mut key_chunk = [0u8; CHUNK_SIZE];
            if getrandom::getrandom(&mut key_chunk).is_err() {
                let error_msg = serde_json::to_string(&ServerMessage::Error {
                    message: "Random generation failed".to_string(),
                }).unwrap_or_default();
                let _ = ws.send_with_str(&error_msg);
                return;
            }

            // Encode as base64 for JSON transport
            let key_base64 = base64_encode(&key_chunk);

            // Send key chunk
            let chunk_msg = serde_json::to_string(&ServerMessage::KeyChunk {
                index: i,
                data: key_base64,
            }).unwrap_or_default();
            
            let _ = ws.send_with_str(&chunk_msg);
        }

        // Send completion
        let complete_msg = serde_json::to_string(&ServerMessage::SessionComplete {
            total_chunks: chunk_count,
        }).unwrap_or_default();
        let _ = ws.send_with_str(&complete_msg);

        console_log!("[VernamSession] Sent {} key chunks", chunk_count);
    }
}

/// Simple base64 encoding
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    let mut result = String::with_capacity((data.len() + 2) / 3 * 4);
    
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;
        
        result.push(ALPHABET[b0 >> 2] as char);
        result.push(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);
        
        if chunk.len() > 1 {
            result.push(ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
        } else {
            result.push('=');
        }
        
        if chunk.len() > 2 {
            result.push(ALPHABET[b2 & 0x3f] as char);
        } else {
            result.push('=');
        }
    }
    
    result
}
