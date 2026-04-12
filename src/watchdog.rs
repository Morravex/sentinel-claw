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

//! Self-protection watchdog module.
//!
//! Monitors sentinel's own installation integrity to detect agent tampering.
//! Checks shell profile sentinel blocks, shims directory, and LD_PRELOAD
//! environment variable every 30 seconds. Sends Telegram alerts on tamper detection.

use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::Duration;
use teloxide::prelude::*;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Shell profile files that should contain sentinel PATH injection blocks.
const SHELL_PROFILES: &[&str] = &[".bashrc", ".zshrc", ".profile"];

/// Current sentinel marker lines.
const SENTINEL_BEGIN: &str = "# --- SENTINEL CLAW SHIMS [BEGIN] ---";
const SENTINEL_END: &str = "# --- SENTINEL CLAW SHIMS [END] ---";

/// Legacy marker from older setup scripts.
const SENTINEL_LEGACY: &str = "# --- SENTINEL CLAW AUTOMATIC SHIMS ---";

/// Shims directory — root-owned, outside /home, agent-proof.
const SHIMS_DIR: &str = "/opt/sentinel/shims";

/// DB table name for integrity hashes.
const TABLE: &str = "integrity_hashes";

/// How often the watchdog polls (seconds).
const POLL_INTERVAL_SECS: u64 = 30;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Types of tampering the watchdog can detect.
#[derive(Debug, Clone)]
pub enum TamperEvent {
    /// Sentinel block was removed or modified in a shell profile.
    ShellProfileModified { profile: String },
    /// The shims directory no longer exists.
    ShimsDeleted,
    /// Files inside the shims directory were added, removed, or modified.
    ShimsCorrupted,
    /// LD_PRELOAD is no longer set in sentinel's own process environment.
    LdPreloadCleared,
}

impl std::fmt::Display for TamperEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ShellProfileModified { profile } => {
                write!(f, "Agent removed sentinel from {}", profile)
            }
            Self::ShimsDeleted => write!(f, "Shims directory deleted"),
            Self::ShimsCorrupted => write!(f, "Shims directory contents modified"),
            Self::LdPreloadCleared => write!(f, "LD_PRELOAD env var cleared"),
        }
    }
}

impl TamperEvent {
    /// Human-readable alert string for Telegram / log output.
    fn alert_label(&self) -> String {
        match self {
            Self::ShellProfileModified { profile } => {
                format!("🛡️ TAMPER DETECTED: Agent removed sentinel from {}", profile)
            }
            Self::ShimsDeleted => {
                "🛡️ TAMPER DETECTED: Shims directory deleted".to_string()
            }
            Self::ShimsCorrupted => {
                "🛡️ TAMPER DETECTED: Shims directory contents modified".to_string()
            }
            Self::LdPreloadCleared => {
                "🛡️ TAMPER DETECTED: LD_PRELOAD env var cleared from sentinel".to_string()
            }
        }
    }
}

// ---------------------------------------------------------------------------
// DB bootstrap
// ---------------------------------------------------------------------------

/// Create the `integrity_hashes` table if it does not already exist.
fn ensure_table() {
    let conn_mutex = crate::shield::get_db_connection();
    let conn = conn_mutex.lock().unwrap();
    let _ = conn.execute(
        &format!(
            "CREATE TABLE IF NOT EXISTS {} (
                component TEXT PRIMARY KEY,
                path      TEXT NOT NULL,
                hash      TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )",
            TABLE
        ),
        [],
    );
}

// ---------------------------------------------------------------------------
// Hashing helpers
// ---------------------------------------------------------------------------

/// Return lowercase hex SHA-256 digest of `data`.
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Hash sentinel marker lines in a profile file.
///
/// Returns the hash of the normalised sentinel block content (lines between
/// BEGIN/END markers, or legacy marker line), or `None` if no sentinel
/// markers are found in the file.
fn hash_sentinel_block(path: &Path) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    let sentinel_lines = extract_sentinel_lines(&content);
    if sentinel_lines.is_empty() {
        None
    } else {
        Some(sha256_hex(sentinel_lines.join("\n").as_bytes()))
    }
}

/// Pull the lines that belong to sentinel blocks out of a shell profile.
fn extract_sentinel_lines(content: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut in_block = false;

    for line in content.lines() {
        if line.contains(SENTINEL_BEGIN) {
            in_block = true;
        }
        if in_block {
            lines.push(line.to_string());
        }
        if line.contains(SENTINEL_END) {
            in_block = false;
        }
        // Legacy marker — single line, no begin/end pair.
        if line.contains(SENTINEL_LEGACY) && !in_block {
            lines.push(line.to_string());
        }
    }
    lines
}

/// Deterministic SHA-256 of the entire shims directory.
///
/// Hashes directory entries (sorted by name) and their contents so that any
/// addition, removal, or modification changes the digest.
fn hash_shims_directory() -> Option<String> {
    let shim_dir = Path::new(SHIMS_DIR);

    if !shim_dir.exists() {
        return None;
    }

    let mut entries: Vec<_> = std::fs::read_dir(shim_dir)
        .ok()?
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.file_name());

    let mut combined = String::new();
    for entry in &entries {
        combined.push_str(&entry.file_name().to_string_lossy());
        combined.push('\n');
        if entry.path().is_file() {
            if let Ok(bytes) = std::fs::read(entry.path()) {
                combined.push_str(&sha256_hex(&bytes));
                combined.push('\n');
            }
        }
    }
    Some(sha256_hex(combined.as_bytes()))
}

// ---------------------------------------------------------------------------
// DB persistence
// ---------------------------------------------------------------------------

fn store_hash(component: &str, path: &str, hash: &str) {
    let conn_mutex = crate::shield::get_db_connection();
    let conn = conn_mutex.lock().unwrap();
    let _ = conn.execute(
        &format!(
            "INSERT OR REPLACE INTO {} (component, path, hash, updated_at)
             VALUES (?1, ?2, ?3, CURRENT_TIMESTAMP)",
            TABLE
        ),
        rusqlite::params![component, path, hash],
    );
}

fn get_stored_hash(component: &str) -> Option<String> {
    let conn_mutex = crate::shield::get_db_connection();
    let conn = conn_mutex.lock().unwrap();
    conn.query_row(
        &format!("SELECT hash FROM {} WHERE component = ?1", TABLE),
        rusqlite::params![component],
        |row| row.get::<_, String>(0),
    )
    .ok()
}

// ---------------------------------------------------------------------------
// Snapshot — establish baseline
// ---------------------------------------------------------------------------

/// Compute and persist baseline integrity hashes for all monitored components.
///
/// Call once at sentinel startup (after launcher sets up shims / LD_PRELOAD)
/// and again whenever the installation is repaired.
pub fn snapshot_integrity() {
    ensure_table();

    // Shell profiles
    if let Some(home) = dirs::home_dir() {
        for profile in SHELL_PROFILES {
            let path = home.join(profile);
            if path.exists() {
                if let Some(hash) = hash_sentinel_block(&path) {
                    store_hash(
                        &format!("profile:{}", profile),
                        &path.to_string_lossy(),
                        &hash,
                    );
                }
            }
        }
    }

    // Shims directory
    if let Some(hash) = hash_shims_directory() {
        store_hash("shims", SHIMS_DIR, &hash);
    }

    // LD_PRELOAD
    if let Ok(ld) = std::env::var("LD_PRELOAD") {
        if !ld.is_empty() {
            store_hash("ld_preload", &ld, &sha256_hex(ld.as_bytes()));
        }
    }

    crate::logger::log_event(
        crate::logger::LogSource::Shield,
        crate::logger::LogLevel::Info,
        "Watchdog: Integrity baseline snapshot stored",
        None,
    );
}

// ---------------------------------------------------------------------------
// Integrity check
// ---------------------------------------------------------------------------

/// Compare current state against the stored baseline.
///
/// Returns a list of `TamperEvent`s — empty means everything is clean.
fn check_integrity() -> Vec<TamperEvent> {
    let mut events = Vec::new();

    // 1. Shell profiles
    if let Some(home) = dirs::home_dir() {
        for profile in SHELL_PROFILES {
            let path = home.join(profile);
            let component = format!("profile:{}", profile);
            let stored = get_stored_hash(&component);

            if stored.is_some() {
                match hash_sentinel_block(&path) {
                    Some(current) if Some(&current) == stored.as_ref() => { /* clean */ }
                    _ => events.push(TamperEvent::ShellProfileModified {
                        profile: profile.to_string(),
                    }),
                }
            }
        }
    }

    // 2. Shims directory (root-owned at /opt/sentinel/shims)
    let shim_dir = Path::new(SHIMS_DIR);
    let shims_stored = get_stored_hash("shims");

    if shims_stored.is_some() {
        if !shim_dir.exists() {
            events.push(TamperEvent::ShimsDeleted);
        } else {
            match hash_shims_directory() {
                Some(current) if Some(&current) == shims_stored.as_ref() => { /* clean */ }
                _ => events.push(TamperEvent::ShimsCorrupted),
            }
        }
    }

    // 3. LD_PRELOAD
    let ld_stored = get_stored_hash("ld_preload");
    if ld_stored.is_some() {
        match std::env::var("LD_PRELOAD") {
            Ok(v) if !v.is_empty() && Some(sha256_hex(v.as_bytes())) == ld_stored => { /* clean */ }
            _ => events.push(TamperEvent::LdPreloadCleared),
        }
    }

    events
}

// ---------------------------------------------------------------------------
// Monitor loop (tokio task)
// ---------------------------------------------------------------------------

/// Spawn the watchdog as a long-lived tokio task.
///
/// * `bot_token` / `chat_id` — Telegram credentials for alert delivery.
pub fn start_monitor(bot_token: String, chat_id: String) {
    ensure_table();

    tokio::spawn(async move {
        let bot = Bot::new(&bot_token);
        let mut interval = tokio::time::interval(Duration::from_secs(POLL_INTERVAL_SECS));

        crate::logger::log_event(
            crate::logger::LogSource::Shield,
            crate::logger::LogLevel::Info,
            "Watchdog: Self-protection monitor started (30 s interval)",
            None,
        );

        loop {
            interval.tick().await;

            let events = check_integrity();
            for event in &events {
                let alert = event.alert_label();

                // Log locally
                crate::logger::log_event(
                    crate::logger::LogSource::Shield,
                    crate::logger::LogLevel::Error,
                    &alert,
                    None,
                );

                // Telegram notification
                let tg_msg = format!("{}\nTime: {}", alert, chrono::Local::now().format("%Y-%m-%d %H:%M:%S"));
                let _ = bot
                    .send_message(chat_id.clone(), &tg_msg)
                    .await;

                // Auto-repair: re-snapshot so we only alert once per incident.
                snapshot_integrity();
            }
        }
    });
}
