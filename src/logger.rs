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

use tokio::sync::broadcast;
use chrono::Local;
use serde::Serialize;
use std::sync::OnceLock;

#[derive(Debug, Serialize, Clone)]
pub struct AuditLog {
    pub timestamp: String,
    pub source: LogSource,
    pub level: LogLevel,
    pub message: String,
    pub details: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub enum LogSource {
    Proxy,
    Intercept,
    Shield,
    Harness,
    Bridge,
    Vault,
}

#[derive(Debug, Serialize, Clone)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
    Veto,
    Secret,
}

static LOG_SENDER: OnceLock<broadcast::Sender<AuditLog>> = OnceLock::new();

pub fn get_log_sender() -> &'static broadcast::Sender<AuditLog> {
    LOG_SENDER.get_or_init(|| {
        let (tx, _rx) = broadcast::channel(100);
        tx
    })
}

pub fn log_event(source: LogSource, level: LogLevel, message: &str, details: Option<&str>) {
    let log = AuditLog {
        timestamp: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        source,
        level,
        message: message.to_string(),
        details: details.map(|d| d.to_string()),
    };

    // Print to console (for immediate feedback)
    let color = match log.level {
        LogLevel::Veto => "\x1b[31m[VETO]\x1b[0m",   // Red
        LogLevel::Secret => "\x1b[33m[SHIELD]\x1b[0m", // Yellow
        LogLevel::Warn => "\x1b[35m[WARN]\x1b[0m",   // Magenta
        LogLevel::Error => "\x1b[41m[ERROR]\x1b[0m",  // Red Background
        LogLevel::Info => "\x1b[32m[INFO]\x1b[0m",    // Green
    };

    println!("{}: {} {}", log.timestamp, color, log.message);

    // Broadcast to subscribers
    let tx = get_log_sender();
    let _ = tx.send(log);
}

pub async fn start_log_stream() {
    let tx = get_log_sender();
    let mut rx = tx.subscribe();
    
    println!("📡 Real-time Command Log Stream Started.");
    while let Ok(_log) = rx.recv().await {
        // Here we could emit to a WebSocket, TUI, or log file
        // For now, it's captured by the broadcast system
    }
}
