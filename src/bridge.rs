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

use teloxide::prelude::*;
use teloxide::types::{InlineKeyboardButton, InlineKeyboardMarkup};
use tokio::sync::oneshot;
use dashmap::DashMap;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use rusqlite::params;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct InterceptRequest {
    pub command: String,
    pub pid: Option<u32>,
    pub id: String,
    pub agent_id: Option<String>,
    pub cwd: Option<String>,
}

use std::sync::RwLock;

pub struct TelegramBridge {
    bot: Bot,
    bot_token: String,
    chat_id: String,
    pending: Arc<DashMap<String, oneshot::Sender<CommandDecision>>>,
    history: Arc<DashMap<String, bool>>, // Command -> Allowed
    safelist: Arc<DashMap<String, bool>>,
    modes: Arc<DashMap<String, String>>, // "DEFAULT" or "AGENT:<id>" or "PID:<pid>"
    pid_map: Arc<DashMap<u32, String>>, // PID -> AgentID (Learning map)
    pii_enabled: Arc<RwLock<bool>>,
    snapshot_enabled: Arc<RwLock<bool>>,
    states: Arc<DashMap<i64, ConversationState>>,
}

#[derive(Debug, Clone)]
pub enum ConversationState {
    Idle,
    AwaitingKey,
    AwaitingProvider(String),
    AwaitingPII,
    AwaitingPIIType(String),
}

#[derive(Debug, Clone)]
pub enum CommandDecision {
    Approve,
    Deny,
    SafeTry,
    Always,
}

impl TelegramBridge {
    pub fn new(bot_token: &str, chat_id: &str) -> Self {
        let pending = Arc::new(DashMap::new());
        let history = Arc::new(DashMap::new());
        let safelist = Arc::new(DashMap::new());
        let modes = Arc::new(DashMap::new());
        modes.insert("DEFAULT".to_string(), "balanced".to_string());
        let mut initial_pii = true;

        // Load Governance State from DB
        let conn_mutex = crate::shield::get_db_connection();
        let conn = match conn_mutex.lock() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("DB lock poisoned in TelegramBridge::new: {}", e);
                e.into_inner()
            }
        };
        
        // Load Safelist
        if let Ok(mut stmt) = conn.prepare("SELECT key FROM sentinel_governance WHERE category = 'safelist'") {
            let keys = stmt.query_map([], |row| row.get::<_, String>(0)).unwrap();
            for key in keys {
                if let Ok(k) = key { safelist.insert(k, true); }
            }
        }

        // Load Modes (All categories)
        if let Ok(mut stmt) = conn.prepare("SELECT key, value FROM sentinel_governance WHERE category = 'config' AND key LIKE 'autonomy_mode%'") {
             let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))).unwrap();
             for row in rows {
                 if let Ok((k, v)) = row {
                     let actual_key = k.strip_prefix("autonomy_mode:").unwrap_or("DEFAULT");
                     modes.insert(actual_key.to_string(), v);
                 }
             }
        }

        // Load PII Setting
        if let Ok(p) = conn.query_row("SELECT value FROM sentinel_governance WHERE key = 'pii_enabled'", [], |row| row.get::<_, String>(0)) {
            initial_pii = p == "true";
        }

        let mut initial_snapshot = true;
        if let Ok(p) = conn.query_row("SELECT value FROM sentinel_governance WHERE key = 'snapshot_enabled'", [], |row| row.get::<_, String>(0)) {
            initial_snapshot = p == "true";
        }

        Self {
            bot: Bot::new(bot_token),
            bot_token: bot_token.to_string(),
            chat_id: chat_id.to_string(),
            pending,
            history,
            safelist,
            modes,
            pid_map: Arc::new(DashMap::new()),
            pii_enabled: Arc::new(RwLock::new(initial_pii)),
            snapshot_enabled: Arc::new(RwLock::new(initial_snapshot)),
            states: Arc::new(DashMap::new()),
        }
    }

    pub async fn request_approval(&self, req: &InterceptRequest) -> CommandDecision {
        // 0. Check Safelist (Permanent Allowance)
        if self.safelist.contains_key(&req.command) {
            crate::logger::log_event(crate::logger::LogSource::Bridge, crate::logger::LogLevel::Info, &format!("SAFELIST_HIT: {}", req.command), None);
            return CommandDecision::Approve;
        }

        // 1. Resolve Autonomy Mode (PID -> Agent -> Default)
        if let Some(pid) = req.pid {
            if let Some(agent_id) = &req.agent_id {
                self.pid_map.insert(pid, agent_id.clone());
            }
        }

        let current_mode = if let Some(pid) = req.pid {
            self.modes.get(&format!("PID:{}", pid))
                .map(|m| m.value().clone())
                .or_else(|| {
                    req.agent_id.as_ref().and_then(|id| self.modes.get(&format!("AGENT:{}", id)).map(|m| m.value().clone()))
                })
                .unwrap_or_else(|| self.modes.get("DEFAULT").map(|m| m.value().clone()).unwrap_or_else(|| "balanced".to_string()))
        } else {
            req.agent_id.as_ref().and_then(|id| self.modes.get(&format!("AGENT:{}", id)).map(|m| m.value().clone()))
                .unwrap_or_else(|| self.modes.get("DEFAULT").map(|m| m.value().clone()).unwrap_or_else(|| "balanced".to_string()))
        };

        match current_mode.as_str() {
            "permissive" => return CommandDecision::Approve,
            "autonomous" => return CommandDecision::Approve,
            _ => {} 
        }

        let (tx, rx) = oneshot::channel();
        self.pending.insert(req.id.clone(), tx);

        let msg = format!(
            "🛡️ <b>SentinelClaw Approval Needed</b>\n\n<b>Command:</b> <code>{}</code>\n<b>Agent:</b> <code>{}</code>\n<b>PID:</b> <code>{}</code>\n\n<b>Risk Category:</b> CRITICAL",
            req.command,
            req.agent_id.as_deref().unwrap_or("unknown"),
            req.pid.unwrap_or(0)
        );

        let keyboard = InlineKeyboardMarkup::new(vec![
            vec![
                InlineKeyboardButton::callback("✅ ALLOW", format!("a:{}", req.id)),
                InlineKeyboardButton::callback("❌ DENY", format!("d:{}", req.id)),
            ],
            vec![
                InlineKeyboardButton::callback("🛡️ SAFE-TRY", format!("s:{}", req.id)),
                InlineKeyboardButton::callback("🔒 ALWAYS", format!("p:{}", req.id)),
            ]
        ]);

        if let Err(e) = self.bot
            .send_message(self.chat_id.clone(), msg)
            .parse_mode(teloxide::types::ParseMode::Html)
            .reply_markup(keyboard)
            .await 
        {
            eprintln!("❌ Telegram Send Error: {}", e);
            self.pending.remove(&req.id);
            return CommandDecision::Deny;
        }

        // Wait for response with a 5-minute timeout (300s)
        match tokio::time::timeout(std::time::Duration::from_secs(300), rx).await {
            Ok(Ok(decision)) => {
                let approved = matches!(decision, CommandDecision::Approve | CommandDecision::SafeTry | CommandDecision::Always);
                self.history.insert(req.command.clone(), approved);
                
                if matches!(decision, CommandDecision::Always) {
                    self.safelist.insert(req.command.clone(), true);
                    {
                        let conn_mutex = crate::shield::get_db_connection();
                        let conn = conn_mutex.lock().unwrap();
                        let _ = conn.execute(
                            "INSERT OR REPLACE INTO sentinel_governance (key, value, category) VALUES (?, ?, ?)",
                            params![req.command, "true", "safelist"],
                        );
                    }
                    crate::logger::log_event(crate::logger::LogSource::Bridge, crate::logger::LogLevel::Info, &format!("SAFELIST_ADD: {}", req.command), None);
                }
                decision
            },
            _ => {
                self.pending.remove(&req.id);
                CommandDecision::Deny // Default to DENY on timeout
            }
        }
    }

    pub async fn start_polling(&self) {
        let bot = self.bot.clone();
        let pending = self.pending.clone();
        let history = self.history.clone();
        let safelist = self.safelist.clone();
        let modes = self.modes.clone();
        let states = self.states.clone();
        let chat_id_str = self.chat_id.clone();

        println!("📡 Sentinel Bridge: Polling Registered.");
        
        use crate::logger::{log_event, LogLevel, LogSource};
        log_event(LogSource::Bridge, LogLevel::Info, "Sentinel Bridge: Polling Started.", None);
        
        // Finalize Startup Message
        let _ = bot.send_message(self.chat_id.clone(), "🛡️ <b>SentinelClaw v0.0.1 ONLINE</b>\n\nSecurity Bridge: <code>READY</code>\nAudit Log: <code>ACTIVE</code>\n\nUse /commands to pull the governance menu.")
            .parse_mode(teloxide::types::ParseMode::Html)
            .await;

        let handler = dptree::entry()
            .branch(Update::filter_callback_query().endpoint(
                move |bot: Bot, q: CallbackQuery, pending: Arc<DashMap<String, oneshot::Sender<CommandDecision>>>| async move {
                    if let Some(data) = q.data {
                        let parts: Vec<&str> = data.split(':').collect();
                        if parts.len() == 2 {
                            let action = parts[0];
                            let id = parts[1];
                            
                            if let Some((_, tx)) = pending.remove(id) {
                                let decision = match action {
                                    "a" => CommandDecision::Approve,
                                    "d" => CommandDecision::Deny,
                                    "s" => CommandDecision::SafeTry,
                                    "p" => CommandDecision::Always,
                                    _ => CommandDecision::Deny,
                                };
                                let _ = tx.send(decision);
                                let label = match action { "a" => "Allowed", "d" => "Denied", "s" => "Safe-Try", "p" => "Always", _ => "Unknown" };
                                let _ = bot.answer_callback_query(q.id).text(label).await;
                                
                                if let Some(msg) = q.message {
                                    let _ = bot.edit_message_text(msg.chat.id, msg.id, format!("Decision: {}", label.to_uppercase())).await;
                                }
                            }
                        }
                    }
                    respond(())
                },
            ))
            .branch(Update::filter_message().endpoint(
                move |bot: Bot, msg: Message, chat_id: String, history: Arc<DashMap<String, bool>>, safelist: Arc<DashMap<String, bool>>, modes: Arc<DashMap<String, String>>, pii_enabled: Arc<RwLock<bool>>, snapshot_enabled: Arc<RwLock<bool>>, states: Arc<DashMap<i64, ConversationState>>| async move {
                    if msg.chat.id.to_string() != chat_id { return respond(()); }
                    use crate::logger::{log_event, LogLevel, LogSource};
                    
                    if let Some(text) = msg.text() {
                        let user_id = msg.chat.id.0;
                        let current_state = states.get(&user_id).map(|s| s.value().clone()).unwrap_or(ConversationState::Idle);

                        match (current_state, text) {
                            (ConversationState::Idle, "/add_key") => {
                                states.insert(user_id, ConversationState::AwaitingKey);
                                let _ = bot.send_message(msg.chat.id, "🗝️ <b>Add New API Key</b>\n\nPlease enter the raw API key you wish to vault:").parse_mode(teloxide::types::ParseMode::Html).await;
                                return respond(());
                            },
                            (ConversationState::AwaitingKey, _) => {
                                let key = text.to_string();
                                states.insert(user_id, ConversationState::AwaitingProvider(key));
                                let _ = bot.send_message(msg.chat.id, "🏭 <b>Enter Provider</b>\n\nWhat service is this key for? (e.g., OpenAI, AWS, Supabase, Redis):").parse_mode(teloxide::types::ParseMode::Html).await;
                                return respond(());
                            },
                            (ConversationState::AwaitingProvider(key), _) => {
                                let provider = text.to_string();
                                states.insert(user_id, ConversationState::Idle);
                                
                                use crate::shield::SecretShield;
                                let ghost_id = SecretShield::add_global_secret(&provider, &key);
                                
                                let success_msg = format!(
                                    "✅ <b>Key Vaulted Successfully</b>\n\n<b>Provider:</b> <code>{}</code>\n<b>Ghost ID:</b> <code>{}</code>\n\nSentinel has encrypted the real key and mapped it to this ID in the identity mesh.\n\n⚠️ <b>SECURITY ADVICE:</b> Please delete your message containing the raw API key from this chat history now.",
                                    provider.to_uppercase(), ghost_id
                                );
                                let _ = bot.send_message(msg.chat.id, success_msg).parse_mode(teloxide::types::ParseMode::Html).await;
                                return respond(());
                            },
                            (ConversationState::Idle, "/add_pii") => {
                                states.insert(user_id, ConversationState::AwaitingPII);
                                let _ = bot.send_message(msg.chat.id, "👤 <b>Vault New PII</b>\n\nEnter the sensitive data (Name, Email, etc.) to vault:").parse_mode(teloxide::types::ParseMode::Html).await;
                                return respond(());
                            },
                            (ConversationState::AwaitingPII, _) => {
                                let val = text.to_string();
                                states.insert(user_id, ConversationState::AwaitingPIIType(val));
                                let _ = bot.send_message(msg.chat.id, "🏷️ <b>Enter Data Type</b>\n\ne.g., email, name, address, ssn:").parse_mode(teloxide::types::ParseMode::Html).await;
                                return respond(());
                            },
                            (ConversationState::AwaitingPIIType(val), _) => {
                                let ptype = text.to_string();
                                states.insert(user_id, ConversationState::Idle);
                                
                                use crate::shield::SecretShield;
                                let ghost_id = SecretShield::add_global_pii(&ptype, &val);
                                
                                let success_msg = format!(
                                    "✅ <b>PII Vaulted Successfully</b>\n\n<b>Type:</b> <code>{}</code>\n<b>Ghost ID:</b> <code>{}</code>\n\nSentinel will now automatically redact this PII and replace it with this stable ID.",
                                    ptype.to_uppercase(), ghost_id
                                );
                                let _ = bot.send_message(msg.chat.id, success_msg).parse_mode(teloxide::types::ParseMode::Html).await;
                                return respond(());
                            },
                            _ => {}
                        }

                        match text {
                            "/status" => {
                                let cur_mode = modes.get("DEFAULT").map(|m| m.value().clone()).unwrap_or_else(|| "balanced".to_string());
                                let pii = *pii_enabled.read().unwrap();
                                let snapshots = *snapshot_enabled.read().unwrap();
                                let s_count = safelist.len();
                                let h_count = history.len();
                                let active_agents = modes.len() - 1; // Exclude DEFAULT

                                let status = format!(
                                    "🛡️ <b>Sentinel Status: ONLINE</b>\n\nTrust Level: <code>{}</code>\nPII Shield: <code>{}</code>\nSnapshotting: <code>{}</code>\nSafelist Active: <code>{} entries</code>\nCustom Agent Policies: <code>{}</code>\nRecent Sessions: <code>{}</code>\n\nSentinel v0.0.1",
                                    cur_mode.to_uppercase(), 
                                    if pii { "ACTIVE" } else { "DISABLED" },
                                    if snapshots { "ENABLED" } else { "DISABLED" },
                                    s_count, active_agents, h_count
                                );
                                let _ = bot.send_message(msg.chat.id, status).parse_mode(teloxide::types::ParseMode::Html).await;
                            },
                            "/history" => {
                                let h_text: String = history.iter().take(10).map(|e| format!("• {} <code>{}</code>", if *e.value() { "✅" } else { "❌" }, e.key())).collect::<Vec<_>>().join("\n");
                                let _ = bot.send_message(msg.chat.id, format!("<b>📜 Recent Audit Events:</b>\n\n{}", if h_text.is_empty() { "Empty" } else { &h_text })).parse_mode(teloxide::types::ParseMode::Html).await;
                            },
                            "/strict" | "/balanced" | "/autonomous" | "/permissive" | "/autostrict" => {
                                let new_mode = text.trim_start_matches('/');
                                modes.insert("DEFAULT".to_string(), new_mode.to_string());
                                {
                                    let conn_mutex = crate::shield::get_db_connection();
                                    let conn = conn_mutex.lock().unwrap();
                                    let _ = conn.execute(
                                        "INSERT OR REPLACE INTO sentinel_governance (key, value, category) VALUES (?, ?, ?)",
                                        params!["autonomy_mode:DEFAULT", new_mode, "config"],
                                    );
                                }
                                log_event(LogSource::Bridge, LogLevel::Warn, &format!("MODE_EVOLUTION: Global Autonomy shifted to {}", new_mode), None);
                                let _ = bot.send_message(msg.chat.id, format!("⚖️ <b>Sentinel Global Pivot:</b> Autonomy set to <code>{}</code>", new_mode.to_uppercase())).parse_mode(teloxide::types::ParseMode::Html).await;
                            },
                            s if s.starts_with("/mode") => {
                                let parts: Vec<&str> = text.split_whitespace().collect();
                                if parts.len() == 3 {
                                    let target = parts[1];
                                    let new_mode = parts[2];
                                    
                                    let key = if target.chars().all(|c| c.is_numeric()) {
                                        format!("PID:{}", target)
                                    } else {
                                        format!("AGENT:{}", target)
                                    };

                                    modes.insert(key.clone(), new_mode.to_string());
                                    {
                                        let conn_mutex = crate::shield::get_db_connection();
                                        let conn = conn_mutex.lock().unwrap();
                                        let _ = conn.execute(
                                            "INSERT OR REPLACE INTO sentinel_governance (key, value, category) VALUES (?, ?, ?)",
                                            params![format!("autonomy_mode:{}", key), new_mode, "config"],
                                        );
                                    }
                                    let _ = bot.send_message(msg.chat.id, format!("⚖️ <b>Per-Agent Pivot:</b> {} now set to <code>{}</code>", target, new_mode.to_uppercase())).parse_mode(teloxide::types::ParseMode::Html).await;
                                } else {
                                    let _ = bot.send_message(msg.chat.id, "📖 <b>Usage:</b> <code>/mode &lt;pid_or_agent_id&gt; &lt;mode&gt;</code>\nExample: <code>/mode 1234 strict</code>").parse_mode(teloxide::types::ParseMode::Html).await;
                                }
                            },
                            "/allowlist" => {
                                let l_text: String = safelist.iter().map(|e| format!("• <code>{}</code>", e.key())).collect::<Vec<_>>().join("\n");
                                let _ = bot.send_message(msg.chat.id, format!("<b>🔒 Persistent Safelist:</b>\n\n{}", if l_text.is_empty() { "Empty" } else { &l_text })).parse_mode(teloxide::types::ParseMode::Html).await;
                            },
                            "/reboot" | "/restart" => {
                                let _ = bot.send_message(msg.chat.id, "♻️ <b>Sentinel Rebooting:</b> Cycling the security appliance...").parse_mode(teloxide::types::ParseMode::Html).await;
                                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                                std::process::exit(0); // Docker-compose will restart it
                            },
                            s if s.starts_with("/rollback") => {
                                let parts: Vec<&str> = text.split_whitespace().collect();
                                if parts.len() == 2 {
                                    if let Ok(pid_val) = parts[1].parse::<i32>() {
                                        crate::launcher::restore_workspace(nix::unistd::Pid::from_raw(pid_val));
                                        let _ = bot.send_message(msg.chat.id, format!("♻️ <b>Workspace Rollback:</b> Environment for PID {} restored to pre-SafeTry state.", pid_val)).parse_mode(teloxide::types::ParseMode::Html).await;
                                    } else {
                                        let _ = bot.send_message(msg.chat.id, "⚠️ Invalid PID format.").await;
                                    }
                                } else {
                                    let _ = bot.send_message(msg.chat.id, "📖 <b>Usage:</b> <code>/rollback &lt;pid&gt;</code>").parse_mode(teloxide::types::ParseMode::Html).await;
                                }
                            },
                            "/pii_on" | "/pii_off" => {
                                let status = text == "/pii_on";
                                {
                                    let mut p = pii_enabled.write().unwrap();
                                    *p = status;
                                }
                                {
                                    let conn_mutex = crate::shield::get_db_connection();
                                    let conn = conn_mutex.lock().unwrap();
                                    let _ = conn.execute(
                                        "INSERT OR REPLACE INTO sentinel_governance (key, value, category) VALUES (?, ?, ?)",
                                        params!["pii_enabled", if status { "true" } else { "false" }, "config"],
                                    );
                                }
                                let _ = bot.send_message(msg.chat.id, format!("🛡️ <b>PII Shield:</b> Target state set to <code>{}</code>", if status { "ON" } else { "OFF" })).parse_mode(teloxide::types::ParseMode::Html).await;
                            },
                            "/snapshot_on" | "/snapshot_off" => {
                                let status = text == "/snapshot_on";
                                {
                                    let mut p = snapshot_enabled.write().unwrap();
                                    *p = status;
                                }
                                {
                                    let conn_mutex = crate::shield::get_db_connection();
                                    let conn = conn_mutex.lock().unwrap();
                                    let _ = conn.execute(
                                        "INSERT OR REPLACE INTO sentinel_governance (key, value, category) VALUES (?, ?, ?)",
                                        params!["snapshot_enabled", if status { "true" } else { "false" }, "config"],
                                    );
                                }
                                let _ = bot.send_message(msg.chat.id, format!("♻️ <b>SafeTry Snapshotting:</b> Deployment state set to <code>{}</code>", if status { "ENABLED" } else { "DISABLED" })).parse_mode(teloxide::types::ParseMode::Html).await;
                            },
                            "/clear_mesh" => {
                                use crate::shield::SecretShield;
                                SecretShield::clear_mesh();
                                let _ = bot.send_message(msg.chat.id, "🧹 <b>Identity Mesh Purged:</b> All Ghost ID mappings have been deleted.").parse_mode(teloxide::types::ParseMode::Html).await;
                            },
                            "/logs" => {
                                // Simple text logs for Telegram (the web dashboard has higher fidelity)
                                let _ = bot.send_message(msg.chat.id, "📡 <i>Sentinel Log Stream is active. Open the dashboard at Port 3333 for the full audit trail.</i>").parse_mode(teloxide::types::ParseMode::Html).await;
                            },
                            "/autonomy" => {
                                let menu = "⚖️ <b>Sentinel Autonomy Control</b>\n\n/strict - Manual Veto (Max Security)\n/balanced - Default Analysis\n/autonomous - High Autonomy\n/permissive - Pass-through";
                                let _ = bot.send_message(msg.chat.id, menu).parse_mode(teloxide::types::ParseMode::Html).await;
                            },
                            "/commands" | "/start" | "/help" => {
                                let menu = "🛡️ <b>Sentinel Mission Control</b>\n\n<b>Auditing:</b>\n/status - System Health\n/history - Recent actions\n/allowlist - Trusted commands\n/logs - Audit Stream\n\n<b>Governance:</b>\n/add_key - Vault a new API Key\n/add_pii - Vault sensitive data\n/mode [id|pid] [mode] - Per-Agent trust\n/autonomy - Global trust levels\n/pii_on / pii_off - Toggle PII Shield\n/snapshot_on / snapshot_off - Toggle SafeTry Backup\n/rollback [pid] - Restore from snapshot\n\n<b>Emergency:</b>\n/reboot - Cycle Appliance\n/stop - Kill Gateway";
                                let _ = bot.send_message(msg.chat.id, menu).parse_mode(teloxide::types::ParseMode::Html).await;
                            },
                            "/id" => {
                                let _ = bot.send_message(msg.chat.id, format!("🆔 <b>Chat ID:</b> <code>{}</code>", msg.chat.id)).parse_mode(teloxide::types::ParseMode::Html).await;
                            },
                            "/stop" => {
                                let _ = bot.send_message(msg.chat.id, "💀 <b>SHUTDOWN_SIGNAL_RECEIVED:</b> Powering off SentinelClaw...").parse_mode(teloxide::types::ParseMode::Html).await;
                                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                                std::process::exit(0);
                            },
                            _ => {}
                        }
                    }
                    respond(())
                }
            ));

        let _ = bot.set_my_commands(vec![
            teloxide::types::BotCommand::new("commands", "Mission Control Menu"),
            teloxide::types::BotCommand::new("add_key", "Vault a New API Key"),
            teloxide::types::BotCommand::new("status", "System Grid Health"),
            teloxide::types::BotCommand::new("autonomy", "Control Trust Levels"),
            teloxide::types::BotCommand::new("history", "Recent Audit Events"),
            teloxide::types::BotCommand::new("allowlist", "Trusted Commands"),
            teloxide::types::BotCommand::new("clear_mesh", "Purge Identity Mesh"),
            teloxide::types::BotCommand::new("logs", "Dashboard Access Link"),
            teloxide::types::BotCommand::new("reboot", "Cycle Security Appliance"),
            teloxide::types::BotCommand::new("stop", "Emergency Shutdown"),
        ]).await;

        Dispatcher::builder(bot, handler)
            .dependencies(dptree::deps![pending, history, chat_id_str, safelist, modes, self.pii_enabled.clone(), self.snapshot_enabled.clone(), states])
            .build()
            .dispatch()
            .await;
    }

    pub fn is_pii_enabled(&self) -> bool {
        *self.pii_enabled.read().unwrap()
    }

    pub fn snapshot_enabled(&self) -> bool {
        *self.snapshot_enabled.read().unwrap()
    }

    /// Send a tamper-alert message to the configured Telegram chat.
    pub async fn send_tamper_alert(&self, message: &str) {
        let _ = self.bot
            .send_message(self.chat_id.clone(), message)
            .await;
    }

    /// Expose bot token for external alerting tasks (e.g. watchdog).
    pub fn bot_token(&self) -> String {
        self.bot_token.clone()
    }

    /// Expose chat ID for external alerting tasks (e.g. watchdog).
    pub fn chat_id(&self) -> String {
        self.chat_id.clone()
    }
}
