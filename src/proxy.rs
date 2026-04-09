// Copyright 2026 Morravex
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::config::SentinelConfig;
use crate::harness::LanguageHarness;
use crate::shield::SecretShield;
use crate::vault::SentinelVault;
use axum::{
    body::Body,
    extract::{State, Json},
    http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{any, get, post},
    Router, Extension,
};
use reqwest::Client;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use crate::bridge::{InterceptRequest, TelegramBridge};
use tokio::net::UnixListener;

pub struct UnifiedProxy {
    pub vault: SentinelVault,
    pub harness: LanguageHarness,
    pub http: Client,
    pub cfg: SentinelConfig,
    pub bridge: Option<Arc<TelegramBridge>>,
}

#[derive(Debug, Clone)]
pub struct AgentIdentity(pub String);

impl UnifiedProxy {
    pub fn new(vault: SentinelVault, harness: LanguageHarness, cfg: SentinelConfig) -> Self {
        let bridge = if let (Some(token), Some(chat_id)) = (
            std::env::var("TELEGRAM_BOT_TOKEN").ok(),
            std::env::var("TELEGRAM_CHAT_ID").ok(),
        ) {
            println!("📡 Sentinel Bridge: Online (Telegram Notification Mode)");
            Some(Arc::new(TelegramBridge::new(&token, &chat_id)))
        } else {
            println!("📡 Sentinel Bridge: Offline (Local Rules Mode Only)");
            None
        };

        Self {
            vault,
            harness,
            http: Client::builder()
                .user_agent("openai-python/1.0.0")
                .build()
                .unwrap_or_else(|_| Client::new()),
            cfg,
            bridge,
        }
    }

    pub async fn run(self: Arc<Self>, port: u16) -> Result<(), Box<dyn std::error::Error>> {
        let app = Router::new()
            .route("/health", get(|| async { (StatusCode::OK, "{\"status\": \"sentinel\", \"version\": \"0.0.1\"}") }))
            .route("/v1/register", post(handle_registration))
            .route("/intercept", post(handle_intercept))
            .route("/v1/shim/scrub", post(handle_shim_scrub))
            .fallback(any(handle_proxy))
            .layer(TraceLayer::new_for_http())
            .with_state(self.clone());

        // 1. Start Default HTTP Server (Port 8080)
        let addr = format!("0.0.0.0:{}", port);
        println!("🛰️ Sentinel Local Proxy (HTTP:{}) listening on: http://{}", port, addr);
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        
        let app_cloned = app.clone();
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app_cloned.layer(axum::Extension(AgentIdentity("default".to_string())))).await {
                eprintln!("❌ Default Proxy Error: {}", e);
            }
        });

        // 2. Start Agent-Specific Ports (Per-Agent Isolation)
        println!("🛰️ Spawning Isolated Agent Micro-Proxies...");
        for (name, a_port) in &self.cfg.agents {
            if *a_port == port { continue; } // Skip collision with main port
            let addr = format!("0.0.0.0:{}", a_port);
            println!("   🔗 Agent: {} -> http://{}", name, addr);
            let listener = tokio::net::TcpListener::bind(&addr).await?;
            let agent_name = name.clone();
            let app_agent = app.clone().layer(axum::Extension(AgentIdentity(agent_name.clone())));
            tokio::spawn(async move {
                if let Err(e) = axum::serve(listener, app_agent).await {
                    eprintln!("❌ Isolated Proxy Error [{}]: {}", agent_name, e);
                }
            });
        }

        // 3. Start Unix Socket Listener (v0.0.1 UDS Support)
        let socket_path = &self.cfg.general.socket_path;
        let uds_listener = UnixListener::bind(socket_path)?;
        println!("🛰️ Sentinel Local Proxy (UDS) listening on: {}", socket_path);
        
        // Ensure the socket is accessible on the host
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o666));
        }

        let _ = app.layer(axum::Extension(AgentIdentity("uds_shim".to_string())));
        
        // Manual UDS serving loop (Version Agnostic)
        tokio::spawn(async move {
            loop {
                if let Ok((stream, _)) = uds_listener.accept().await {
                    tokio::spawn(async move {
                        // For Axum 0.7/0.8, we can use hyper directly or just a TCP bridge.
                        // Since we are inside Docker, we'll proxy UDS -> Localhost:8080 (internal)
                        if let Ok(client) = tokio::net::TcpStream::connect("127.0.0.1:8080").await {
                             let (mut uds_read, mut uds_write) = tokio::io::split(stream);
                             let (mut tcp_read, mut tcp_write) = tokio::io::split(client);
                             let _ = tokio::join!(
                                 tokio::io::copy(&mut uds_read, &mut tcp_write),
                                 tokio::io::copy(&mut tcp_read, &mut uds_write)
                             );
                        }
                    });
                } else {
                    break;
                }
            }
        });

        Ok(())
    }
}

async fn handle_intercept(
    State(proxy): State<Arc<UnifiedProxy>>,
    Extension(agent): Extension<AgentIdentity>,
    axum::Json(req): axum::Json<InterceptRequest>,
) -> axum::response::Json<serde_json::Value> {
    use crate::logger::{log_event, LogLevel, LogSource};
    use crate::bridge::CommandDecision;
    
    let agent_name = req.agent_id.as_deref().unwrap_or(&agent.0);
    
    // 0. [VPN-MODE] Materialize Real Secrets/PII from Ghost IDs
    let materialized_command = SecretShield::restore_mesh(&req.command);
    let was_materialized = materialized_command != req.command;
    
    if was_materialized {
        log_event(LogSource::Intercept, LogLevel::Info, &format!("Agent: {}, MATERIALIZED Ghost IDs in command.", agent_name), None);
    }

    log_event(LogSource::Intercept, LogLevel::Info, &format!("Agent: {}, Command: {}", agent_name, materialized_command), None);

    // 1. Audit Command for Shell Risks (Using Materialized Command)
    let risks = SecretShield::audit_shell(&materialized_command);
    
    // 2. Determine if Approval is Needed (v1 risk model)
    // For critical risks or those that need approval, ask the bridge.
    if !risks.is_empty() {
        log_event(LogSource::Intercept, LogLevel::Veto, &format!("VETO: {} - Reason: {}", req.command, risks.join(", ")), None);
        
        if let Some(bridge) = &proxy.bridge {
            println!("📡 Requesting Operator Approval...");
            let decision = bridge.request_approval(&req).await;
            match decision {
                CommandDecision::Approve | CommandDecision::SafeTry | CommandDecision::Always => {
                    log_event(LogSource::Intercept, LogLevel::Info, &format!("OPERATOR_GRANTED: {}", materialized_command), None);
                    
                    if matches!(decision, CommandDecision::SafeTry) && bridge.snapshot_enabled() {
                         if let Some(pid_val) = req.pid {
                             crate::launcher::snapshot_workspace(nix::unistd::Pid::from_raw(pid_val as i32));
                         }
                    }

                    return axum::response::Json(serde_json::json!({
                        "allowed": true,
                        "score": 100,
                        "category": "critical",
                        "reason": if matches!(decision, CommandDecision::SafeTry) { "Safe-Try (Environment Snapshotted)" } else { "Operator Authorization Granted" },
                        "redacted_command": materialized_command
                    }));
                },
                CommandDecision::Deny => {
                    log_event(LogSource::Intercept, LogLevel::Veto, &format!("OPERATOR_DENIED: {}", materialized_command), None);
                }
            }
        }

        return axum::response::Json(serde_json::json!({
            "allowed": false,
            "score": 100,
            "category": "critical",
            "reason": format!("Vetoed: {}", risks.join(", "))
        }));
    }

    // 3. Secret Scan: Check command for NEW embedded secrets
    // Skip re-scrubbing if we just materialized (allows VPN-mode to work)
    if !was_materialized {
        let mut final_scrubbed = materialized_command.clone();
        let mut secret_detected = false;

        if SecretShield::is_known_secret_pattern(&materialized_command) {
            final_scrubbed = SecretShield::scrub(&final_scrubbed, agent_name);
            secret_detected = true;
        }

        // Add Heuristic Entropy Scrubbing for obfuscated secrets (Hex, ROT13, etc)
        let heuristic_scrubbed = SecretShield::scrub_high_entropy(&final_scrubbed, agent_name);
        if heuristic_scrubbed != final_scrubbed {
            final_scrubbed = heuristic_scrubbed;
            secret_detected = true;
        }

        if secret_detected {
            log_event(LogSource::Shield, LogLevel::Secret, &format!("SECRET_IN_COMMAND: Agent {} tried command with NEW or obfuscated secret. Redacted.", agent_name), None);
            return axum::response::Json(serde_json::json!({
                "allowed": true,
                "score": 50,
                "category": "secret_detected",
                "reason": "Secret detected in command — agent should use vault placeholder",
                "redacted_command": final_scrubbed
            }));
        }
    }

    // 4. Auto-Allow Low Risk
    axum::response::Json(serde_json::json!({
        "allowed": true,
        "score": 0,
        "category": "low",
        "reason": "Safe (Local Rules)",
        "redacted_command": materialized_command
    }))
}

/// Transparent byte-level reverse proxy.
/// Reads raw request bytes, scrubs secrets, forwards everything else untouched.
/// Buffers entire response in memory so return as complete bytes.
async fn handle_proxy(
    State(proxy): State<Arc<UnifiedProxy>>,
    Extension(agent): Extension<AgentIdentity>,
    req: Request<Body>,
) -> Response {
    use crate::logger::{log_event, LogLevel, LogSource};
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let query = req.uri().query().map(|q| q.to_string());
    let ct = req.headers().get(header::CONTENT_TYPE).cloned();

    log_event(LogSource::Proxy, LogLevel::Info, &format!("PROXY_CALL [Agent: {}]: {} {}", agent.0, method, path), None);

    // Read raw request body bytes
    let body_bytes = match axum::body::to_bytes(req.into_body(), 10 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            println!("Failed to read body: {}", e);
            return (StatusCode::BAD_REQUEST, "Failed to read body").into_response();
        }
    };

    let body_str = String::from_utf8_lossy(&body_bytes);

    // 1. Audit & Scrub via Harness (Intent + Secrets + Entropy + [EXPERIMENTAL] PII)
    // We pass the raw string, Harness will spawn a blocking task to handle regex + normalizations.
    // Determine PII status from governance mesh (Bridge) or fallback to config
    let pii_enabled = if let Some(bridge) = &proxy.bridge {
        bridge.is_pii_enabled()
    } else {
        proxy.cfg.policy.pii_redaction
    };

    let decision = proxy.harness.audit_context(&body_str, pii_enabled, &agent.0).await;
    
    if !decision.approved {
        println!("🛑 SENTINEL_VETO: {}", decision.reasoning);
        return (StatusCode::FORBIDDEN, format!("SENTINEL_VETO: {}", decision.reasoning)).into_response();
    }

    let forward_bytes = if let Some(redacted) = decision.redacted_payload {
        println!("🛡️ REDACTED: {} -> {} bytes | {} {}", body_bytes.len(), redacted.len(), method, path);
        redacted.into_bytes()
    } else {
        if !body_bytes.is_empty() {
             println!("🚀 FORWARD: {} {} ({}b)", method, path, body_bytes.len());
        }
        body_bytes.to_vec()
    };

    // 2. Resolve provider and upstream (explicit provider required)
    let (provider, upstream_url) = match resolve_provider_and_upstream(&proxy.cfg, &path, query.as_deref()) {
        Some(r) => r,
        None => {
            log_event(LogSource::Proxy, LogLevel::Error, &format!("No provider specified in path: {} [Agent: {}]", path, agent.0), None);
            return (StatusCode::BAD_REQUEST, "No provider specified. Use /{provider}/v1/... (e.g., /openrouter/v1/, /anthropic/v1/, /zai/v1/)").into_response();
        }
    };

    // 3. Vault Key Resolution (Centralized Sentinelty)
    let real_key = match proxy.vault.get_key(&agent.0, &provider) {
        Some(k) => {
            let k_trimmed = k.trim().to_string();
            println!("🗝️  Shield: Resolved key for provider [{}] (len: {})", 
                provider, k_trimmed.len());
            k_trimmed
        },
        None => {
            log_event(LogSource::Vault, LogLevel::Error, &format!("Vault: No API key found for Agent [{}] on Provider [{}]", agent.0, provider), None);
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("No vault key for {}", provider)).into_response();
        }
    };

    // 4. Forward headers
    let mut headers = HeaderMap::new();
    
    // Inject the real key into Authorization
    headers.insert(header::AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {}", real_key)).unwrap());
    
    if let Some(ct) = ct {
        headers.insert(header::CONTENT_TYPE, ct);
    }

    // Add required OpenRouter identifying headers
    headers.insert("HTTP-Referer", HeaderValue::from_static("https://github.com/Morravex/sentinel-claw"));
    headers.insert("X-Title", HeaderValue::from_static("Sentinel Security Appliance"));
    
    // Add User-Agent for Cloudflare bypass (Agnostic)
    headers.insert(header::USER_AGENT, HeaderValue::from_static("openai-python/1.0.0"));

    // 5. Send to upstream
    let rm = match method {
        Method::POST => reqwest::Method::POST,
        Method::PUT => reqwest::Method::PUT,
        Method::PATCH => reqwest::Method::PATCH,
        Method::GET => reqwest::Method::GET,
        Method::DELETE => reqwest::Method::DELETE,
        _ => reqwest::Method::POST,
    };

    let mut builder = proxy.http.request(rm, &upstream_url);
    for (n, v) in headers.iter() {
        builder = builder.header(n.as_str(), v.to_str().unwrap_or(""));
    }
    if !forward_bytes.is_empty() && method != Method::GET {
        builder = builder.body(forward_bytes);
    }

    match builder.send().await {
        Ok(upstream) => {
            let status = StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::OK);
            let upstream_headers = upstream.headers().clone();

            // Buffer ENTIRE response body in memory
            let resp_bytes = match upstream.bytes().await {
                Ok(b) => b,
                Err(e) => {
                    println!("UPSTREAM_READ_ERROR: {}", e);
                    return (StatusCode::BAD_GATEWAY, format!("Upstream read error: {}", e)).into_response();
                }
            };

            // Layer 3: Response Body Scrubbing (Defense-in-Depth)
            // Scrub secrets from the upstream response before returning to the agent.
            // This catches cases where the LLM reproduces secrets in its output.
            let resp_body_str = String::from_utf8_lossy(&resp_bytes);
            let final_bytes = if SecretShield::is_known_secret_pattern(&resp_body_str) ||
                SecretShield::calculate_entropy(&resp_body_str) > 4.5 {
                let scrubbed = SecretShield::scrub(&resp_body_str, &agent.0);
                let heuristic_scrubbed = SecretShield::scrub_high_entropy(&scrubbed, &agent.0);
                if heuristic_scrubbed != resp_body_str {
                    println!("🛡️ RESPONSE_SCRUBBED: {} -> {} bytes | {} {}", resp_bytes.len(), heuristic_scrubbed.len(), method, path);
                    log_event(LogSource::Shield, LogLevel::Secret, &format!("RESPONSE_SCRUBBED: Secrets detected in upstream response for {} {}", method, path), None);
                    heuristic_scrubbed.into_bytes()
                } else if scrubbed != resp_body_str {
                    println!("🛡️ RESPONSE_SCRUBBED: {} -> {} bytes | {} {}", resp_bytes.len(), scrubbed.len(), method, path);
                    log_event(LogSource::Shield, LogLevel::Secret, &format!("RESPONSE_SCRUBBED: Secrets detected in upstream response for {} {}", method, path), None);
                    scrubbed.into_bytes()
                } else {
                    resp_bytes.to_vec()
                }
            } else {
                resp_bytes.to_vec()
            };

            // Build response: exact status + all headers + complete buffered body
            let mut resp = Response::builder().status(status);
            for (k, v) in upstream_headers.iter() {
                if let (Ok(hn), Ok(hv)) = (
                    header::HeaderName::from_bytes(k.as_str().as_bytes()),
                    HeaderValue::from_bytes(v.as_bytes()),
                ) {
                    // Skip hop-by-hop headers that axum re-adds
                    if matches!(hn, header::CONNECTION | header::TRANSFER_ENCODING | header::UPGRADE | header::CONTENT_LENGTH) {
                        continue;
                    }
                    resp = resp.header(hn, hv);
                }
            }
            // Set content-length for the (possibly scrubbed) body
            let content_len = HeaderValue::from_str(&final_bytes.len().to_string()).unwrap();
            resp = resp.header(header::CONTENT_LENGTH, content_len);

            resp.body(Body::from(final_bytes))
                .unwrap_or_else(|_| {
                    (StatusCode::BAD_GATEWAY, "stream error").into_response()
                })
        }
        Err(e) => {
            println!("CLOUD_OFFLINE: {}", e);
            (StatusCode::BAD_GATEWAY, format!("Provider unreachable: {}", e)).into_response()
        }
    }
}

/// Dynamic Multi-Provider Resolution
/// Returns None if no explicit provider is found in the path
fn resolve_provider_and_upstream(cfg: &SentinelConfig, path: &str, query: Option<&str>) -> Option<(String, String)> {
    let p_clean = path.trim_start_matches('/');
    let components: Vec<&str> = p_clean.split('/').collect();
    
    // Require explicit provider in path (e.g. /anthropic/v1/..., /openrouter/v1/...)
    let (provider, actual_path) = if !components.is_empty() && cfg.providers.contains_key(components[0]) {
        let prov = components[0];
        let p_rem = format!("/{}", components[1..].join("/"));
        (prov.to_string(), p_rem)
    } else {
        return None;
    };

    let base_url = cfg.providers.get(&provider).unwrap_or(&cfg.cloud.base_url);
    let base = base_url.trim_end_matches('/');
    let p = actual_path.trim_start_matches('/');
    
    let mut url = if p.is_empty() {
        base.to_string()
    } else if p == "chat/completions" || p.ends_with("/chat/completions") {
        // Special case for chat/completions if using standard OpenAI-like paths
        format!("{}/chat/completions", base)
    } else {
        format!("{}/{}", base, p.trim_start_matches("v1/").trim_start_matches("/v1/"))
    };

    // Generic path fix: if base_url ends in v1 and path starts in v1, don't double it.
    if base.ends_with("/v1") && url.contains("/v1/v1") {
        url = url.replace("/v1/v1", "/v1");
    }

    if let Some(q) = query {
        url = format!("{}?{}", url, q);
    }
    
    Some((provider, url))
}

async fn handle_registration(
    State(proxy): State<Arc<UnifiedProxy>>,
    Json(manifest): Json<crate::harness::MissionManifest>,
) -> StatusCode {
    proxy.harness.register_mission(manifest);
    StatusCode::OK
}

/// Shim Scrub Endpoint: Called by the LD_PRELOAD shim to vault secrets.
/// Receives raw file content, vaults secrets with ghost IDs, returns scrubbed text.
/// Key names are preserved (only the secret value is replaced with a ghost ID).
async fn handle_shim_scrub(
    body: axum::body::Bytes,
) -> axum::response::Json<serde_json::Value> {
    use crate::shield::SecretShield;

    let input = String::from_utf8_lossy(&body);
    let input_str = input.to_string();

    let result = tokio::task::spawn_blocking(move || {
        let mut final_output = SecretShield::scrub(&input_str, "shim");
        
        // Append LLM/agent context comment explaining the ghost ID format
        let has_secrets = final_output.contains("sentinel_secret_") 
            || final_output.contains("sentinel_pii_") 
            || final_output.contains("sentinel_heuristic_");
        if has_secrets {
            final_output.push_str("\n\n# SentinelClaw Shield: Secrets in this file have been replaced with vaulted ghost IDs.\n");
            final_output.push_str("# Format: sentinel_secret_<provider>_<id> (e.g. sentinel_secret_openai_1)\n");
            final_output.push_str("# These ghost IDs are stable references — use them exactly as shown.\n");
            final_output.push_str("# SentinelClaw will automatically restore the real values at runtime when needed.\n");
            final_output.push_str("# Do NOT attempt to decode or replace these IDs yourself.\n");
        }
        
        final_output
    }).await;

    match result {
        Ok(scrubbed) => axum::response::Json(serde_json::json!({
            "scrubbed": scrubbed,
            "length": scrubbed.len()
        })),
        Err(_) => axum::response::Json(serde_json::json!({
            "scrubbed": input.to_string(),
            "length": input.len(),
            "error": "scrub task failed"
        })),
    }
}
