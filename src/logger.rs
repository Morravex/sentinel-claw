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
use std::sync::Mutex;
use std::fs::OpenOptions;
use std::io::Write;
use std::fs;

const MAX_LOG_SIZE: u64 = 10 * 1024 * 1024; // 10MB
const MAX_ROTATED_FILES: u32 = 3;

static LOG_FILE: OnceLock<Mutex<()>> = OnceLock::new();

fn get_log_path() -> String {
    std::env::var("SENTINEL_LOG_PATH").unwrap_or_else(|_| "sentinel.log".to_string())
}

fn rotate_logs(path: &str) {
    // Remove oldest rotated file if it exists
    let oldest = format!("{}.{}", path, MAX_ROTATED_FILES);
    let _ = fs::remove_file(&oldest);

    // Shift existing rotated files: .2 -> .3, .1 -> .2
    for i in (1..MAX_ROTATED_FILES).rev() {
        let from = format!("{}.{}", path, i);
        let to = format!("{}.{}", path, i + 1);
        if fs::metadata(&from).is_ok() {
            let _ = fs::rename(&from, &to);
        }
    }

    // Rename current log to .1
    let _ = fs::rename(path, format!("{}.1", path));
}

fn write_to_file(line: &str) {
    // Acquire the lock to ensure serial writes
    let guard = LOG_FILE.get_or_init(|| Mutex::new(()));
    let _lock = guard.lock().unwrap();

    let path = get_log_path();

    // Check if rotation is needed
    if let Ok(metadata) = fs::metadata(&path) {
        if metadata.len() >= MAX_LOG_SIZE {
            rotate_logs(&path);
        }
    }

    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(file, "{}", line);
    }
}

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

    // Write to log file
    let file_line = format!(
        "{}: [{}] [{}] {}{}",
        log.timestamp,
        match log.level {
            LogLevel::Veto => "VETO",
            LogLevel::Secret => "SHIELD",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
            LogLevel::Info => "INFO",
        },
        match log.source {
            LogSource::Proxy => "Proxy",
            LogSource::Intercept => "Intercept",
            LogSource::Shield => "Shield",
            LogSource::Harness => "Harness",
            LogSource::Bridge => "Bridge",
            LogSource::Vault => "Vault",
        },
        log.message,
        log.details.as_deref().map(|d| format!(" | {}", d)).unwrap_or_default(),
    );
    write_to_file(&file_line);

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
