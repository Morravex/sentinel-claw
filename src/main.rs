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

use std::sync::Arc;
use std::time::Duration;
use sentinel::proxy::UnifiedProxy;
use sentinel::vault::SentinelVault;
use sentinel::harness::LanguageHarness;
use sentinel::shield;
use sentinel::logger;
use sentinel::dashboard;
use sentinel::launcher;
use sentinel::config;

/**
 * Sentinel: The Autonomous Security Gateway (v0.0.1)
 * Strategy: Unified Sentinel Proxy & Secret Protection
 */

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // -1. Initialize Environment
    if let Ok(env_path) = std::env::var("SENTINEL_ENV_PATH") {
        dotenv::from_path(env_path).ok();
    } else {
        dotenv::dotenv().ok();
    }

    // -0.5. Single Instance Enforcement (Latest Wins)
    guard_single_instance();
    
    // 0. Initialize Encrypted Mapping Vault
    let db_path = std::env::var("SENTINEL_DB_PATH").unwrap_or_else(|_| "sentinel.db".to_string());
    if std::path::Path::new(&db_path).is_dir() {
        eprintln!("❌ FATAL Error: {} is a directory, not a file.", db_path);
        eprintln!("   This usually happens in Docker if the file didn't exist before 'compose' bound it.");
        eprintln!("   FIX: Run 'touch {}' on your host and restart the container.", db_path);
        std::process::exit(1);
    }

    let pairing_key = std::env::var("SENTINEL_PAIRING_KEY").expect("❌ SENTINEL_PAIRING_KEY missing in .env. Run ./setup.sh first!");
    shield::SecretShield::init_master_key(&pairing_key);

    // 0.1 [CLI MODE] Sentinel Run: Global Secret Materialization
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 2 && args[1] == "run" {
        let mut arg_idx = 2;
        let mut forced_mode: Option<String> = None;
        let mut agent_name: Option<String> = None;

        // Parse Autonomy Flags & Agent Name
        while arg_idx < args.len() && args[arg_idx].starts_with('-') {
            let flag = args[arg_idx].as_str();
            match flag {
                "-strict" | "--strict" => forced_mode = Some("strict".to_string()),
                "-balanced" | "--balanced" => forced_mode = Some("balanced".to_string()),
                "-autonomous" | "--autonomous" => forced_mode = Some("autonomous".to_string()),
                "-permissive" | "--permissive" => forced_mode = Some("permissive".to_string()),
                "-n" | "--name" => {
                    if arg_idx + 1 < args.len() {
                        agent_name = Some(args[arg_idx + 1].clone());
                        arg_idx += 1;
                    }
                },
                _ => break, // Start of command
            }
            arg_idx += 1;
        }

        if let Some(mode) = forced_mode {
            println!("⚖️ Sentinel: Enforcing Autonomy Mode -> {}", mode.to_uppercase());
            let conn_mutex = shield::get_db_connection();
            let conn = conn_mutex.lock().unwrap();
            let _ = conn.execute(
                "INSERT OR REPLACE INTO sentinel_governance (key, value, category) VALUES (?, ?, ?)",
                rusqlite::params!["autonomy_mode:DEFAULT", mode, "config"],
            );
        }

        if arg_idx >= args.len() {
            eprintln!("❌ Error: No command provided to 'sentinel run'.");
            std::process::exit(1);
        }

        let command_str = &args[arg_idx];
        let child_args: Vec<String> = args[arg_idx + 1..].to_vec();

        // Interpret the agent name from the path if not explicitly provided
        if agent_name.is_none() {
            let mut candidates = Vec::new();
            
            // 1. Gather all segments from command execution and PATH
            candidates.push(command_str.to_string());
            candidates.extend(child_args.clone());
            
            // Resolve actual path for standard binaries to get NPM module names
            if let Ok(real_path) = std::fs::canonicalize(command_str) {
                candidates.push(real_path.to_string_lossy().to_string());
            } else if let Ok(which_path) = which::which(command_str) {
                if let Ok(real_which) = std::fs::canonicalize(&which_path) {
                    candidates.push(real_which.to_string_lossy().to_string());
                } else {
                    candidates.push(which_path.to_string_lossy().to_string());
                }
            }

            // Also add CWD for implicitly executed projects
            if let Ok(cwd) = std::env::current_dir() {
                candidates.push(cwd.to_string_lossy().to_string());
            }

            // Generic terms to ignore
            let generics = [
                "node", "python", "python3", "ruby", "bash", "sh", "zsh", "npx", "npm", "yarn", "pip", "-m",
                "bin", "usr", "local", "dist", "src", "lib", "index", "index.js", "entry.js", "cli.js", "main", 
                "modules", "node_modules", "global", ".npm-global", "env", "venv", ".env", "app", "cmd"
            ];

            let mut final_identity = String::new();

            for candidate in &candidates {
                let parts: Vec<&str> = candidate.split(|c| c == '/' || c == '\\' || c == ' ').collect();
                
                for part in parts.iter().rev() { // Salient identifiers are usually at the leaf
                    let clean_part = part.trim_matches(|c| c == '.' || c == '"' || c == '\'' || c == '-');
                    if clean_part.is_empty() { continue; }

                    let is_generic = generics.iter().any(|&g| clean_part == g);
                    
                    if !is_generic {
                        // Skip NPM org scopes
                        if clean_part.starts_with('@') {
                            continue;
                        }
                        
                        // Extract first segment before logical separator
                        let identity = clean_part
                            .split('-')
                            .next().unwrap_or(clean_part)
                            .split('_')
                            .next().unwrap_or(clean_part)
                            .split('.')
                            .next().unwrap_or(clean_part);
                            
                        if !identity.is_empty() {
                            final_identity = identity.to_string();
                            break;
                        }
                    }
                }
                if !final_identity.is_empty() {
                    break;
                }
            }

            if !final_identity.is_empty() {
                agent_name = Some(final_identity);
            }
        }
        
        launcher::run_agent(agent_name.as_deref(), command_str, &child_args);
        return Ok(());
    }

    // 0.2 Start Streaming Logger (Server Mode Only)
    tokio::spawn(logger::start_log_stream());
    tokio::spawn(dashboard::start_dashboard_server());
    
    // 1. Load Config
    let config_path = std::env::var("SENTINEL_CONFIG_PATH").unwrap_or_else(|_| "sentinel.toml".to_string());
    let config = config::SentinelConfig::load_from(&config_path).unwrap_or_else(|e| {
        // Fallback to example config if the real one is missing
        let example_path = "sentinel.toml.example";
        eprintln!("⚠️ Could not load {}: {}. Trying {}...", config_path, e, example_path);
        config::SentinelConfig::load_from(example_path)
            .expect(&format!("❌ Could not load config from {} or {}", config_path, example_path))
    });
    
    // 2. Initialize Components
    let vault = SentinelVault::new();
    
    // 2.1 Load Per-Agent Isolated Secrets
    for (name, _) in &config.agents {
        vault.load_agent_env(name, &format!(".env-{}", name));
    }
    
    // 3. Initialize Sentinel Shared Components
    let harness = LanguageHarness::new();
    let proxy = Arc::new(UnifiedProxy::new(vault, harness, config.clone()));

    // 4. Start Unified Sentinel Proxy (USP)
    println!("🛰️ Initializing Sentinel Local Proxy (SLP)...");
    
    // Clean stale socket if it exists
    let socket_path = &config.general.socket_path;
    if std::path::Path::new(socket_path).exists() {
        let _ = std::fs::remove_file(socket_path);
    }

    let proxy_cloned = proxy.clone();
    tokio::spawn(async move {
        if let Err(e) = proxy_cloned.run(8080).await {
            eprintln!("❌ Proxy Error: {}", e);
        }
    });

    // 5. Start Sentinel Service (Telegram Bridge + Notification Loop)
    if let Some(bridge) = &proxy.bridge {
        println!("📡 Starting Sentinel Bridge Polling...");
        let bridge_cloned = bridge.clone();
        tokio::spawn(async move {
            bridge_cloned.start_polling().await;
        });
    } else {
        println!("⚠️ Sentinel Bridge disabled (Missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID in .env)");
    }
    
    // Keep alive
    tokio::signal::ctrl_c().await?;
    println!("🛡️ SentinelClaw v0.0.1 Shutting Down...");
    let _ = std::fs::remove_file("/tmp/sentinel.pid");
    Ok(())
}

fn guard_single_instance() {
    let pid_file = "/tmp/sentinel.pid";
    let current_pid = std::process::id();

    if let Ok(old_pid_str) = std::fs::read_to_string(pid_file) {
        if let Ok(old_pid) = old_pid_str.trim().parse::<u32>() {
            if old_pid != current_pid {
                // Verify the PID is actually alive and is a Sentinel process
                #[cfg(unix)]
                {
                    use std::process::Command;
                    let is_alive = Command::new("kill").arg("-0").arg(old_pid.to_string()).status().map(|s| s.success()).unwrap_or(false);
                    
                    if is_alive {
                        // Optional: Check if process name contains 'sentinel'
                        let comm = std::fs::read_to_string(format!("/proc/{}/comm", old_pid)).unwrap_or_default();
                        if comm.contains("sentinel") {
                            println!("⚠️ Sentinel Conflict: Active instance (PID {}) detected. Preempting...", old_pid);
                            let _ = Command::new("kill").arg("-9").arg(old_pid.to_string()).status();
                            std::thread::sleep(Duration::from_millis(500));
                        }
                    }
                }
            }
        }
    }

    if let Err(e) = std::fs::write(pid_file, current_pid.to_string()) {
        eprintln!("⚠️ Warning: Could not write PID lock to {}: {}", pid_file, e);
    }
}
