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

use axum::{
    routing::get,
    response::{Html, sse::{Sse, Event}, IntoResponse},
    Router,
    extract::Request,
    middleware::{self, Next},
    http::{StatusCode, header},
};
use tokio_stream::Stream;
use std::convert::Infallible;
use crate::logger::{get_log_sender};
use std::sync::OnceLock;

static CSRF_TOKEN: OnceLock<String> = OnceLock::new();

fn get_csrf_token() -> &'static str {
    CSRF_TOKEN.get_or_init(|| {
        use rand::Rng;
        let token: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();
        token
    })
}

/// Middleware: Verify Bearer token on all /api/* routes
async fn auth_middleware(request: Request, next: Next) -> impl IntoResponse {
    let path = request.uri().path().to_string();

    // Only enforce auth on API routes
    if path.starts_with("/api/") {
        let expected_token = std::env::var("SENTINEL_PAIRING_KEY").unwrap_or_default();
        if expected_token.is_empty() {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Server misconfigured: no auth key").into_response();
        }

        let auth_header = request.headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        // Accept "Bearer <token>" format
        let token_valid = auth_header
            .strip_prefix("Bearer ")
            .map(|t| t == expected_token)
            .unwrap_or(false);

        if !token_valid {
            return (StatusCode::UNAUTHORIZED, "Unauthorized: invalid or missing Bearer token").into_response();
        }
    }

    next.run(request).await.into_response()
}

pub async fn start_dashboard_server(port: u16) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = Router::new()
        .route("/", get(dashboard_html))
        .route("/api/logs", get(logs_stream))
        .route("/api/mappings", get(get_mappings))
        .route("/api/keys", axum::routing::post(add_key_api))
        .route("/api/csrf-token", get(get_csrf_token_handler))
        .layer(middleware::from_fn(auth_middleware));

    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("🌐 Sentinel Dashboard Live: http://localhost:{}", port);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn get_csrf_token_handler() -> impl IntoResponse {
    axum::response::Json(serde_json::json!({
        "csrf_token": get_csrf_token()
    }))
}

#[derive(serde::Deserialize)]
struct AddKeyRequest {
    provider: String,
    key: String,
    csrf_token: String,
}

async fn add_key_api(axum::Json(payload): axum::Json<AddKeyRequest>) -> impl IntoResponse {
    // Verify CSRF token
    if payload.csrf_token != *get_csrf_token() {
        return (
            StatusCode::FORBIDDEN,
            axum::response::Json(serde_json::json!({
                "status": "error",
                "message": "Invalid CSRF token"
            }))
        ).into_response();
    }

    use crate::shield::SecretShield;
    let ghost_id = SecretShield::add_global_secret(&payload.provider, &payload.key);
    (
        StatusCode::OK,
        axum::response::Json(serde_json::json!({
            "status": "success",
            "ghost_id": ghost_id,
            "message": format!("Key for {} vaulted successfully", payload.provider)
        }))
    ).into_response()
}

async fn dashboard_html() -> Html<&'static str> {
    Html(r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🛡️ Sentinel Dashboard | Security Appliance</title>
    <style>
        :root {
            --bg: #0a0a0f;
            --glass: rgba(20, 20, 30, 0.7);
            --neon-blue: #00f2ff;
            --neon-pink: #ff00ea;
            --neon-green: #39ff14;
            --text-main: #e0e0e0;
            --text-dim: #a0a0a0;
        }

        body {
            margin: 0;
            padding: 0;
            background: var(--bg);
            color: var(--text-main);
            font-family: 'Outfit', system-ui, -apple-system, sans-serif;
            overflow: hidden;
            display: flex;
            height: 100vh;
        }

        /* --- BACKGROUND GRADIENT --- */
        body::before {
            content: '';
            position: fixed;
            top: -50%; left: -50%;
            width: 200%; height: 200%;
            background: radial-gradient(circle at center, #1a1a2e 0%, #0a0a0f 70%);
            z-index: -1;
            animation: rotate 20s linear infinite;
        }

        @keyframes rotate {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        /* --- SIDEBAR --- */
        .sidebar {
            width: 260px;
            background: var(--glass);
            backdrop-filter: blur(20px);
            border-right: 1px solid rgba(255, 255, 255, 0.1);
            display: flex;
            flex-direction: column;
            padding: 2rem 1.5rem;
        }

        .logo {
            font-size: 1.5rem;
            font-weight: 600;
            color: var(--neon-blue);
            margin-bottom: 3rem;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .nav-item {
            padding: 0.8rem 1rem;
            border-radius: 12px;
            margin-bottom: 0.5rem;
            cursor: pointer;
            transition: 0.3s;
            color: var(--text-dim);
            font-size: 1rem;
        }

        .nav-item:hover, .nav-item.active {
            background: rgba(0, 242, 255, 0.1);
            color: var(--neon-blue);
        }

        /* --- VAULT FORM --- */
        .vault-form {
            display: flex;
            flex-direction: column;
            gap: 1rem;
            background: rgba(255,255,255,0.02);
            padding: 1.5rem;
            border-radius: 15px;
            border: 1px solid rgba(255,255,255,0.05);
        }

        .input-group {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }

        .input-group label {
            font-size: 0.8rem;
            color: var(--text-dim);
            text-transform: uppercase;
        }

        input {
            background: rgba(0,0,0,0.3);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 8px;
            padding: 0.8rem;
            color: white;
            font-family: 'JetBrains Mono', ui-monospace, 'Cascadia Code', monospace;
            outline: none;
        }

        input:focus {
            border-color: var(--neon-blue);
        }

        button {
            background: var(--neon-blue);
            color: black;
            border: none;
            padding: 1rem;
            border-radius: 8px;
            font-weight: bold;
            cursor: pointer;
            transition: 0.3s;
        }

        button:hover {
            box-shadow: 0 0 15px var(--neon-blue);
            transform: translateY(-2px);
        }

        /* --- MAIN CONTENT --- */
        .content {
            flex: 1;
            padding: 2rem 3rem;
            display: flex;
            flex-direction: column;
            gap: 2rem;
            overflow-y: auto;
        }

        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .status-badge {
            padding: 0.4rem 1rem;
            background: rgba(57, 255, 20, 0.1);
            border: 1px solid var(--neon-green);
            color: var(--neon-green);
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
        }

        /* --- LOG PANEL --- */
        .card {
            background: var(--glass);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            border: 1px solid rgba(255, 255, 255, 0.05);
            padding: 1.5rem;
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }

        .log-container {
            flex: 1;
            height: 400px;
            background: rgba(0, 0, 0, 0.3);
            border-radius: 12px;
            padding: 1rem;
            font-family: 'JetBrains Mono', ui-monospace, 'Cascadia Code', monospace;
            font-size: 13px;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            gap: 4px;
        }

        .log-entry {
            display: flex;
            gap: 15px;
            padding: 2px 0;
            border-bottom: 1px solid rgba(255,255,255,0.02);
            animation: fadeIn 0.3s ease-out;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(5px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .log-ts { color: var(--text-dim); }
        .log-lvl-info { color: var(--neon-green); }
        .log-lvl-veto { color: #ff3e3e; font-weight: bold; }
        .log-lvl-secret { color: #ffab00; }
        .log-msg { color: #eee; }

        /* --- STATS GRID --- */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }

        .stat-card {
            background: rgba(255,255,255,0.03);
            padding: 1rem;
            border-radius: 15px;
            text-align: center;
        }

        .stat-val {
            font-size: 1.8rem;
            font-weight: bold;
            color: var(--neon-blue);
        }

        .stat-lbl {
            font-size: 0.8rem;
            color: var(--text-dim);
            text-transform: uppercase;
            letter-spacing: 1px;
        }
    </style>
</head>
<body>
    <div class="sidebar">
        <div class="logo">🛡️ SentinelClaw</div>
        <div class="nav-item active">Live Telemetry</div>
        <div class="nav-item">Identity Mesh</div>
        <div class="nav-item">Vault Audit</div>
        <div class="nav-item">System Policy</div>
        
        <div style="margin-top: auto; font-size: 0.8rem; color: var(--text-dim);">
            Sentinel v0.0.1<br>
            Morravex Advanced Security
        </div>
    </div>

    <div class="content">
        <div class="header">
            <div>
                <h1 style="margin: 0; font-size: 2rem;">Security Telemetry</h1>
                <p style="color: var(--text-dim); margin-top: 5px;">Real-time event materialization stream.</p>
            </div>
            <div class="status-badge">Sentinel Active (8080-8089)</div>
        </div>

        <div class="stats-grid">
            <div class="stat-card"><div class="stat-val" id="stat-proxies">0</div><div class="stat-lbl">Active Proxies</div></div>
            <div class="stat-card"><div class="stat-val" id="stat-secrets">0</div><div class="stat-lbl">Ghost ID Mappings</div></div>
            <div class="stat-card"><div class="stat-val" id="stat-vetos">0</div><div class="stat-lbl">Total Vetos</div></div>
        </div>

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 2rem;">
            <div class="card">
                <div style="font-weight: 600;">🗝️ Vault New Secret</div>
                <div class="vault-form">
                    <div class="input-group">
                        <label>Provider</label>
                        <input type="text" id="vault-provider" placeholder="e.g. OpenAI, Supabase, AWS">
                    </div>
                    <div class="input-group">
                        <label>API Key</label>
                        <input type="password" id="vault-key" placeholder="Paste your raw key here">
                    </div>
                    <button onclick="vaultKey()">Securely Vault Key</button>
                    <p id="vault-status" style="font-size: 0.8rem; margin: 0; min-height: 1.2rem;"></p>
                    <p style="font-size: 0.75rem; color: var(--neon-pink); margin-top: 10px;">⚠️ <b>SECURITY ADVICE:</b> Clear your browser history or close this tab after vaulting to ensure no traces remain in the DOM.</p>
                </div>
            </div>

            <div class="card">
                <div style="font-weight: 600; display: flex; justify-content: space-between;">
                    Live Events
                    <span id="log-count" style="color: var(--text-dim); font-size: 0.8rem;">0 events</span>
                </div>
                <div class="log-container" id="logs">
                    <div class="log-entry">
                        <span class="log-ts">00:00:00</span>
                        <span class="log-lvl-info">[SYSM]</span>
                        <span class="log-msg">Initializing Sentinel Telemetry Link...</span>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        const logContent = document.getElementById('logs');
        const statSecrets = document.getElementById('stat-secrets');
        const statVetos = document.getElementById('stat-vetos');
        const logCountEl = document.getElementById('log-count');
        
        let mappingsCount = 0;
        let vetoCount = 0;
        let logCount = 0;
        let csrfToken = '';

        // Fetch CSRF token on load with auth
        function getAuthHeaders(contentType) {
            const token = sessionStorage.getItem('sentinel_token') || '';
            const headers = { 'Authorization': 'Bearer ' + token };
            if (contentType) headers['Content-Type'] = contentType;
            return headers;
        }

        // Prompt for token on load
        (function initAuth() {
            const stored = sessionStorage.getItem('sentinel_token');
            if (!stored) {
                const input = prompt('Enter Sentinel Pairing Key to access dashboard:');
                if (input) {
                    sessionStorage.setItem('sentinel_token', input);
                }
            }
            // Fetch CSRF token
            fetch('/api/csrf-token', { headers: getAuthHeaders() })
                .then(r => r.json())
                .then(data => { csrfToken = data.csrf_token; })
                .catch(() => {});
        })();

        function vaultKey() {
            const provider = document.getElementById('vault-provider').value;
            const key = document.getElementById('vault-key').value;
            const status = document.getElementById('vault-status');

            if (!provider || !key) {
                status.innerText = '❌ Please enter both provider and key.';
                status.style.color = '#ff3e3e';
                return;
            }

            status.innerText = '🔐 Vaulting...';
            status.style.color = 'var(--neon-blue)';

            fetch('/api/keys', {
                method: 'POST',
                headers: getAuthHeaders('application/json'),
                body: JSON.stringify({ provider, key, csrf_token: csrfToken })
            })
            .then(r => r.json())
            .then(data => {
                if (data.status === 'error') {
                    status.innerText = '❌ ' + data.message;
                    status.style.color = '#ff3e3e';
                    return;
                }
                status.innerText = '✅ Success! ID: ' + data.ghost_id;
                status.style.color = 'var(--neon-green)';
                document.getElementById('vault-key').value = '';
                refreshMappings();
            })
            .catch(e => {
                status.innerText = '❌ Error vaulting key.';
                status.style.color = '#ff3e3e';
            });
        }

        function refreshMappings() {
            fetch('/api/mappings', { headers: getAuthHeaders() })
                .then(r => r.json())
                .then(data => {
                    mappingsCount = data.length;
                    statSecrets.innerText = mappingsCount;
                });
        }

        // --- FETCH INITIAL MAPPINGS ---
        refreshMappings();

        // --- SUBSCRIBE TO LIVE LOGS (SSE) ---
        // EventSource doesn't support custom headers, so we pass token as query param
        const tokenParam = sessionStorage.getItem('sentinel_token') || '';
        const eventSource = new EventSource('/api/logs?token=' + encodeURIComponent(tokenParam));
        eventSource.onmessage = (event) => {
            const audit = JSON.parse(event.data);
            logCount++;
            logCountEl.innerText = logCount + ' events';

            const entry = document.createElement('div');
            entry.className = 'log-entry';
            
            // SECURITY: Use textContent instead of innerHTML to prevent XSS
            const tsSpan = document.createElement('span');
            tsSpan.className = 'log-ts';
            tsSpan.textContent = audit.timestamp.split(' ')[1];

            const lvlSpan = document.createElement('span');
            lvlSpan.className = 'log-lvl-' + audit.level.toLowerCase();
            lvlSpan.textContent = '[' + audit.level.toUpperCase() + ']';

            const msgSpan = document.createElement('span');
            msgSpan.className = 'log-msg';
            msgSpan.textContent = audit.message;

            entry.appendChild(tsSpan);
            entry.appendChild(lvlSpan);
            entry.appendChild(msgSpan);

            logContent.prepend(entry);
            if (logContent.children.length > 200) logContent.lastChild.remove();

            if (audit.level === 'Veto') {
                vetoCount++;
                statVetos.innerText = vetoCount;
            }
            if (audit.level === 'Secret') {
                mappingsCount++;
                statSecrets.innerText = mappingsCount;
            }
        };

        // --- DYNAMIC STATUS ---
        document.getElementById('stat-proxies').innerText = '10';
    </script>
</body>
</html>
    "#)
}

async fn logs_stream(axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    // Verify token from query param for SSE (EventSource doesn't support headers)
    let expected_token = std::env::var("SENTINEL_PAIRING_KEY").unwrap_or_default();
    let provided_token = params.get("token").map(|s| s.as_str()).unwrap_or("");
    let authorized = !expected_token.is_empty() && provided_token == expected_token;

    let stream = async_stream::stream! {
        if !authorized {
            return;
        }
        let tx = get_log_sender();
        let mut rx = tx.subscribe();
        while let Ok(log) = rx.recv().await {
            yield Ok(Event::default().data(serde_json::to_string(&log).unwrap()));
        }
    };

    Sse::new(stream)
}

async fn get_mappings() -> impl IntoResponse {
    let db = crate::shield::get_db_connection();
    let conn = match db.lock() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("DB lock poisoned in get_mappings: {}", e);
            e.into_inner()
        }
    };
    
    let mut stmt = match conn.prepare("SELECT id, category FROM sentinel_mesh") {
        Ok(s) => s,
        Err(e) => {
            return axum::response::Json(serde_json::json!({"error": format!("Query prepare failed: {}", e)}));
        }
    };

    let rows: Vec<serde_json::Value> = match stmt.query_map([], |row| {
        Ok(serde_json::json!({
            "id": row.get::<_, String>(0)?,
            "category": row.get::<_, String>(1)?,
        }))
    }) {
        Ok(iter) => iter.filter_map(|r| r.ok()).collect(),
        Err(e) => {
            return axum::response::Json(serde_json::json!({"error": format!("Query failed: {}", e)}));
        }
    };

    axum::response::Json(serde_json::Value::Array(rows))
}
