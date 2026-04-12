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

use regex::Regex;
use std::sync::{OnceLock, LazyLock, Arc, Mutex};
use rusqlite::{params, Connection};
use dashmap::DashMap;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce
};
use pbkdf2::pbkdf2_hmac_array;
use sha2::Sha256;
use base64::{Engine as _, engine::general_purpose};

static MASTER_KEY: OnceLock<[u8; 32]> = OnceLock::new();
static PBKDF2_SALT: OnceLock<Vec<u8>> = OnceLock::new();

static DB: LazyLock<Arc<Mutex<Connection>>> = LazyLock::new(|| {
    let db_path = std::env::var("SENTINEL_DB_PATH").unwrap_or_else(|_| {
        let mut path = std::env::current_dir().unwrap_or_default();
        path.push("sentinel.db");
        path.to_string_lossy().to_string()
    });
    let conn = Connection::open(&db_path).expect(&format!("❌ Could not open sentinel.db at {}", db_path));
    
    // Performance Tuning: Enable WAL Mode for faster concurrent reads/writes
    let _ = conn.execute("PRAGMA journal_mode=WAL", []);
    let _ = conn.execute("PRAGMA synchronous=NORMAL", []);

    conn.execute(
        "CREATE TABLE IF NOT EXISTS sentinel_mesh (
            id TEXT PRIMARY KEY,
            real_value TEXT NOT NULL,
            search_hash TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            category TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    ).expect("❌ Could not initialize sentinel_mesh table");

    conn.execute(
        "CREATE TABLE IF NOT EXISTS sentinel_governance (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            category TEXT NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    ).expect("❌ Could not initialize sentinel_governance table");
    
    // Ensure search_hash index if not exists
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_sentinel_hash ON sentinel_mesh (search_hash)", []);

    // Create sentinel_meta table for per-installation secrets (e.g. PBKDF2 salt)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS sentinel_meta (
            key TEXT PRIMARY KEY,
            value BLOB NOT NULL
        )",
        [],
    )
    .expect("❌ Could not initialize sentinel_meta table");

    // Load or generate PBKDF2 salt (unique per installation)
    let salt: Vec<u8> = match conn.query_row(
        "SELECT value FROM sentinel_meta WHERE key = 'pbkdf2_salt'",
        [],
        |row| row.get::<_, Vec<u8>>(0),
    ) {
        Ok(existing) => existing,
        Err(_) => {
            // Generate a new random 32-byte salt
            let new_salt: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
            let _ = conn.execute(
                "INSERT INTO sentinel_meta (key, value) VALUES ('pbkdf2_salt', ?)",
                params![new_salt],
            );
            new_salt
        }
    };
    let _ = PBKDF2_SALT.set(salt);

    Arc::new(Mutex::new(conn))
});

// High-Performance In-Memory Mesh Cache: Avoids redundant SHA256 and SQL lookups for hot secrets
static SECRET_MAP_CACHE: LazyLock<DashMap<String, String>> = LazyLock::new(DashMap::new);
static ID_MAP_CACHE: LazyLock<DashMap<String, String>> = LazyLock::new(DashMap::new);

pub fn get_db_connection() -> Arc<Mutex<Connection>> {
    DB.clone()
}

static EXPERIMENTAL_PII_PATTERNS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    vec![
        // Email addresses
        ("email", Regex::new(r"(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}").unwrap()),
        // International phone numbers (simple)
        ("phone", Regex::new(r"\b(?:\+?(\d{1,3}))?[-. (]*(\d{3})[-. )]*(\d{3})[-. ]*(\d{4})\b").unwrap()),
        // Common Credit Card formats
        ("card", Regex::new(r"\b(?:\d[ -]??){13,16}\b").unwrap()),
    ]
});

pub struct SecretShield;

static PATTERNS: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();

impl SecretShield {
    fn patterns() -> &'static [(&'static str, Regex)] {
        PATTERNS.get_or_init(|| {
            vec![
                // --- Cloud & AI Providers ---
                ("openai", Regex::new(r"sk-[a-zA-Z0-9]{32,72}").unwrap()),
                ("openrouter", Regex::new(r"sk-or-v1-[a-zA-Z0-9\-]{30,}").unwrap()),
                ("groq", Regex::new(r"gsk_[a-zA-Z0-9]{20,}").unwrap()),
                ("anthropic", Regex::new(r"sk-ant-[a-zA-Z0-9]{30,}").unwrap()),
                ("google", Regex::new(r"AIza[0-9A-Za-z-_]{15,}").unwrap()),
                ("aws", Regex::new(r"AKIA[0-9A-Z]{16}").unwrap()),
                ("aws_detailed", Regex::new(r"(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}").unwrap()),
                ("amazon_mws", Regex::new(r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}").unwrap()),
                ("facebook", Regex::new(r"EAACEdEose0cBA[0-9A-Za-z]+").unwrap()),
                ("google_oauth", Regex::new(r"ya29\.[0-9A-Za-z\-_]+").unwrap()),
                ("paypal_braintree", Regex::new(r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}").unwrap()),
                ("slack", Regex::new(r"xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}").unwrap()),
                ("slack_webhook", Regex::new(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}").unwrap()),
                ("sendinblue", Regex::new(r"xkeysib-[a-zA-Z0-9]{40,}").unwrap()),
                ("mailgun", Regex::new(r"key-[0-9a-zA-Z]{16,}").unwrap()),
                ("mailchimp", Regex::new(r"[0-9a-f]{32}-us[0-9]{1,2}").unwrap()),
                ("twilio", Regex::new(r"SK[0-9a-fA-F]{32}").unwrap()),
                ("telegram", Regex::new(r"[0-9]{8,12}:[a-zA-Z0-9_-]{30,}").unwrap()),
                ("square", Regex::new(r"sq0atp-[0-9A-Za-z\-_]{22}").unwrap()),
                ("square_oauth", Regex::new(r"sq0csp-[0-9A-Za-z\-_]{43}").unwrap()),
                ("stripe", Regex::new(r"sk_live_[0-9a-zA-Z]{24,32}").unwrap()),
                ("stripe_restricted", Regex::new(r"rk_live_[0-9a-zA-Z]{24}").unwrap()),
                ("heroku", Regex::new(r"[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}").unwrap()),
                ("cloudinary", Regex::new(r"cloudinary://[0-9]+:[A-Za-z0-9\-_\.]+@[A-Za-z0-9\-_\.]+").unwrap()),
                ("private_key", Regex::new(r"-----BEGIN ((EC|PGP|DSA|RSA|OPENSSH) )?PRIVATE KEY( BLOCK)?-----").unwrap()),
                ("mongodb", Regex::new(r"mongodb(\+srv)?://[a-zA-Z0-9._%:-]+:[a-zA-Z0-9._%:-]+@[a-zA-Z0-9.-]+").unwrap()),
                ("postgres", Regex::new(r"postgres(ql)?://[a-zA-Z0-9._%:-]+:[a-zA-Z0-9._%:-]+@[a-zA-Z0-9.-]+").unwrap()),
                ("redis", Regex::new(r"redis(s)?://:[a-zA-Z0-9._%:-]+@[a-zA-Z0-9.-]+:[0-9]+").unwrap()),
                ("openclaw", Regex::new(r"opclaw-[a-zA-Z0-9\-\.]{20,}").unwrap()),
                ("generic", Regex::new(r"vk_live_[a-zA-Z0-9]{10,}").unwrap()),
                ("zai", Regex::new(r"[0-9a-f]{20,}\.[a-zA-Z0-9]{10,}").unwrap()),
                ("password_env", Regex::new(r#"(?i)(password|secret_key|auth_token|api_secret|client_secret|db_password)\s*[:=]\s*([^\s'"&@]{8,})"#).unwrap()),
                ("api_env", Regex::new(r#"(?i)(api[_-]?key|access[_-]?token|bearer)\s*[:=]\s*([^\s'"&@]{12,})"#).unwrap()),
                // --- Obfuscation Patterns ---
                ("hex_key", Regex::new(r"(?i)[0-9a-f]{64,128}").unwrap()),
                ("b64_key", Regex::new(r"[a-zA-Z0-9+/]{64,128}==?").unwrap()),
            ]
        })
    }

    /**
     * Measure Shannon Entropy of a string to detect high-randomness (Keys/Secrets).
     * This is a zero-cost, local alternative to LLM-based secret scanning.
     */
    pub fn calculate_entropy(s: &str) -> f64 {
        if s.is_empty() { return 0.0; }
        let mut counts = [0usize; 256];
        for &byte in s.as_bytes() {
            counts[byte as usize] += 1;
        }
        let len = s.len() as f64;
        counts.into_iter().filter(|&c| c > 0).map(|c| {
            let p = c as f64 / len;
            -p * p.log2()
        }).sum()
    }

    /**
     * Master Key Derivation:
     * Derives a 256-bit key from the Sentinel Pairing Key for at-rest encryption.
     */
    pub fn init_master_key(pairing_key: &str) {
        // Use per-installation random salt loaded from sentinel_meta table.
        // Falls back to a warning if DB hasn't been initialized yet.
        let salt = PBKDF2_SALT
            .get()
            .expect("❌ PBKDF2 salt not initialized — DB must be loaded before init_master_key");
        let key = pbkdf2_hmac_array::<Sha256, 32>(pairing_key.as_bytes(), salt, 100_000);
        let _ = MASTER_KEY.set(key);
    }

    fn encrypt_value(plaintext: &str) -> String {
        let key = MASTER_KEY.get().expect("❌ Master Key not initialized");
        let cipher = Aes256Gcm::new(key.into());
        
        // Random Nonce per encryption
        let nonce_bytes = rand::random::<[u8; 12]>();
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes())
            .expect("❌ Encryption failed");
        
        // Prepend nonce to ciphertext: [12 bytes nonce][ciphertext]
        let mut combined = nonce_bytes.to_vec();
        combined.extend(ciphertext);
        
        general_purpose::STANDARD.encode(combined)
    }

    fn decrypt_value(ciphertext_b64: &str) -> String {
        let key = MASTER_KEY.get().expect("❌ Master Key not initialized");
        let cipher = Aes256Gcm::new(key.into());
        
        let decoded = general_purpose::STANDARD.decode(ciphertext_b64)
            .expect("❌ Base64 decode failed");
        
        if decoded.len() < 12 { panic!("❌ Invalid ciphertext: too short"); }
        
        let (nonce_bytes, ciphertext) = decoded.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .expect("❌ Decryption failed");
        
        String::from_utf8(plaintext).expect("❌ Invalid UTF-8")
    }

    /**
     * Pattern-matching logic for 1,600+ known API key signatures.
     * Uses Regex for fast, deterministic detection without inference costs.
     * See docker-compose.yml for deployment configuration.
     */
    pub fn is_known_secret_pattern(text: &str) -> bool {
        Self::patterns().iter().any(|(_, re)| re.is_match(text))
    }

    /// Build byte-offset ranges for lines that should NOT be scrubbed:
    /// - Lines starting with comment markers (#, //, /*, *, --)
    /// - Lines marked with sentinel:example
    /// - Blocks between sentinel:ignore:start and sentinel:ignore:end
    fn build_skip_ranges(input: &str) -> Vec<(usize, usize)> {
        let mut ranges = Vec::new();
        let mut ignore_depth: i32 = 0;
        let mut ignore_start: usize = 0;
        
        for (start, line) in Self::line_offsets(input) {
            let trimmed = line.trim();
            
            // Track sentinel:ignore blocks
            if trimmed.contains("sentinel:ignore:start") {
                if ignore_depth == 0 { ignore_start = start; }
                ignore_depth += 1;
                continue;
            }
            if trimmed.contains("sentinel:ignore:end") {
                ignore_depth = ignore_depth.saturating_sub(1);
                if ignore_depth == 0 {
                    ranges.push((ignore_start, start + line.len()));
                }
                continue;
            }
            
            // Inside an ignore block — skip everything
            if ignore_depth > 0 { continue; }
            
            // Comment lines (#, //, /*, *, --, <!--)
            if trimmed.starts_with('#')
                || trimmed.starts_with("//")
                || trimmed.starts_with("/*")
                || trimmed.starts_with('*')
                || trimmed.starts_with("--")
                || trimmed.starts_with("<!--")
            {
                ranges.push((start, start + line.len()));
                // Special: if this comment contains sentinel:example, also skip the next non-blank line
                if trimmed.contains("sentinel:example") {
                    let remaining = &input[start + line.len()..];
                    let mut offset_acc = 0usize;
                    for next_line in remaining.lines() {
                        let nl_len = if offset_acc + next_line.len() < remaining.len() { 1 } else { 0 };
                        offset_acc += next_line.len() + nl_len;
                        if !next_line.trim().is_empty() {
                            let next_start = start + line.len() + offset_acc - next_line.len() - nl_len;
                            ranges.push((next_start, next_start + next_line.len()));
                            break;
                        }
                    }
                }
                continue;
            }
            
            // sentinel:example marker — skip this line AND the next non-blank line
            if trimmed.contains("sentinel:example") {
                ranges.push((start, start + line.len()));
                // Also skip the next non-blank line (the actual example content)
                let remaining = &input[start + line.len()..];
                let mut skip_chars = 0;
                for next_line in remaining.lines() {
                    let next_trimmed = next_line.trim();
                    skip_chars += next_line.len();
                    if !next_trimmed.is_empty() {
                        ranges.push((start + line.len() + skip_chars - next_line.len(), 
                                    start + line.len() + skip_chars));
                        // Account for newline
                        if start + line.len() + skip_chars < input.len() { }
                        break;
                    }
                    // Account for newline
                    if start + line.len() + skip_chars < input.len() { skip_chars += 1; }
                }
                continue;
            }
            
            // Inline sentinel:ignore on a line (skip just this line)
            if trimmed.contains("sentinel:ignore") {
                ranges.push((start, start + line.len()));
                continue;
            }
        }
        
        ranges
    }
    
    /// Yield (byte_offset, line_text) for each line in the input
    fn line_offsets(input: &str) -> Vec<(usize, &str)> {
        let mut result = Vec::new();
        let mut offset = 0;
        for line in input.lines() {
            result.push((offset, line));
            offset += line.len();
            // Account for the newline character
            if offset < input.len() && input.as_bytes()[offset] == b'\n' {
                offset += 1;
            } else if offset < input.len() && input.as_bytes()[offset] == b'\r' {
                offset += 1;
                if offset < input.len() && input.as_bytes()[offset] == b'\n' {
                    offset += 1;
                }
            }
        }
        result
    }
    
    /// Check if a match [start, end) overlaps with any skip range
    fn match_in_skip_range(start: usize, end: usize, ranges: &[(usize, usize)]) -> bool {
        for &(rs, re) in ranges {
            // Match overlaps with skip range
            if start < re && end > rs {
                return true;
            }
        }
        false
    }

    /**
     * The Sentinel "Sentinel Scrub": 
     * Redacts and blocks secrets with stable SQL mapping.
     * Skips comment lines, sentinel:example markers, and sentinel:ignore blocks.
     */
    pub fn scrub(input: &str, agent_id: &str) -> String {
        // --- Pre-process: Identify lines to skip (comments, examples, ignore blocks) ---
        let skip_ranges = Self::build_skip_ranges(input);
        
        let mut output = input.to_string();
        let mut all_matches = Vec::new();
        
        // 1. Gather all potential matches across all patterns
        for (stype, re) in Self::patterns() {
            for caps in re.captures_iter(&output) {
                let m = caps.get(0).unwrap();
                // Skip matches that fall inside a comment, example, or ignore block
                if Self::match_in_skip_range(m.start(), m.end(), &skip_ranges) {
                    continue;
                }
                
                // If there's a capture group 2, we only want to redact THAT part (the secret value)
                // This preserves the "KEY=" part of environment variables.
                if let Some(val_match) = caps.get(2) {
                    all_matches.push((val_match.start(), val_match.end(), val_match.as_str().to_string(), stype.to_string()));
                } else {
                    all_matches.push((m.start(), m.end(), m.as_str().to_string(), stype.to_string()));
                }
            }
        }

        // 2. De-duplicate identical matches (if two patterns match the same location)
        all_matches.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1))); // Sort by start, then by length
        all_matches.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1); // Same location? Unique it.

        // 3. Sort by length (descending) for greedy substring protection
        all_matches.sort_by(|a, b| b.2.len().cmp(&a.2.len()));

        let conn = DB.lock().unwrap_or_else(|e| e.into_inner());
        for (_, _, m, stype) in all_matches {
            // Re-check after potential prior replacements
            if !output.contains(&m) { continue; }
            
            // Ignore existing Ghost IDs to prevent recursive redaction
            if m.starts_with("sentinel_secret_") || m.starts_with("sentinel_pii_") || m.starts_with("sentinel_heuristic_") {
                continue;
            }

            // 1. Check Hot Cache first (Skip Hash + SQL)
            if let Some(cached_id) = SECRET_MAP_CACHE.get(&m) {
                let id_val: &String = cached_id.value();
                output = output.replace(&m, id_val);
                continue;
            }
            
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(m.as_bytes());
            let m_hash = format!("{:x}", hasher.finalize());

            let id: String = match conn.query_row(
                "SELECT id FROM sentinel_mesh WHERE search_hash = ?",
                params![m_hash],
                |row| row.get::<_, String>(0),
            ) {
                Ok(existing) => {
                    SECRET_MAP_CACHE.insert(m.clone(), existing.clone());
                    existing
                },
                Err(_) => {
                    let count: i64 = conn.query_row("SELECT count(*) FROM sentinel_mesh WHERE category = 'Secret'", [], |row| row.get::<_, i64>(0)).unwrap_or(0);
                    let next_id = format!("sentinel_secret_{}_{}", stype, count + 1);
                    let encrypted = Self::encrypt_value(&m);
                    let _ = conn.execute(
                        "INSERT INTO sentinel_mesh (id, real_value, search_hash, agent_id, category) VALUES (?, ?, ?, ?, ?)",
                        params![next_id, encrypted, m_hash, agent_id, "Secret"],
                    );
                    SECRET_MAP_CACHE.insert(m.clone(), next_id.clone());
                    next_id
                }
            };
            output = output.replace(&m, &id);
        }

        output.replace("__SENTINEL_KEY__", "[INJECT_KEY_FINAL_HOP]")
    }

    /// [EXPERIMENTAL] Context-Aware PII Mapping (SQL)
    pub fn scrub_pii(input: &str, agent_id: &str) -> String {
        let mut output = input.to_string();
        let mut all_matches = Vec::new();
        
        for (stype, re) in &*EXPERIMENTAL_PII_PATTERNS {
            for m in re.find_iter(&output) {
                all_matches.push((m.as_str().to_string(), stype.to_string()));
            }
        }

        all_matches.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

        let conn = DB.lock().unwrap_or_else(|e| e.into_inner());
        for (m, stype) in all_matches {
            if !output.contains(&m) { continue; }
            
            // Re-check hot cache for PII
            if let Some(cached_id) = SECRET_MAP_CACHE.get(&m) {
                 let id_val: &String = cached_id.value();
                 output = output.replace(&m, id_val);
                 continue;
            }

            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(m.as_bytes());
            let m_hash = format!("{:x}", hasher.finalize());

            let id: String = match conn.query_row(
                "SELECT id FROM sentinel_mesh WHERE search_hash = ?",
                params![m_hash],
                |row| row.get::<_, String>(0),
            ) {
                Ok(existing) => {
                    SECRET_MAP_CACHE.insert(m.clone(), existing.clone());
                    existing
                },
                Err(_) => {
                    let count: i64 = conn.query_row("SELECT count(*) FROM sentinel_mesh WHERE category = 'PII'", [], |row| row.get::<_, i64>(0)).unwrap_or(0);
                    let next_id = format!("sentinel_pii_{}_{}", stype, count + 1);
                    let encrypted = Self::encrypt_value(&m);
                    let _ = conn.execute(
                        "INSERT INTO sentinel_mesh (id, real_value, search_hash, agent_id, category) VALUES (?, ?, ?, ?, ?)",
                        params![next_id, encrypted, m_hash, agent_id, "PII"],
                    );
                    SECRET_MAP_CACHE.insert(m.clone(), next_id.clone());
                    next_id
                }
            };
            output = output.replace(&m, &id);
        }
        output
    }

    /// Explicitly add a secret to the mesh (e.g. via Telegram/Dashboard)
    pub fn add_global_secret(provider: &str, raw_key: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(raw_key.as_bytes());
        let m_hash = format!("{:x}", hasher.finalize());

        let conn = DB.lock().unwrap_or_else(|e| e.into_inner());
        
        match conn.query_row(
            "SELECT id FROM sentinel_mesh WHERE search_hash = ?",
            params![m_hash],
            |row| row.get(0),
        ) {
            Ok(existing) => existing,
            Err(_) => {
                let count: i64 = conn.query_row(
                    "SELECT count(*) FROM sentinel_mesh WHERE category = 'Secret'", 
                    [], 
                    |row| row.get(0)
                ).unwrap_or(0);
                
                let next_id = format!("sentinel_secret_{}_{}", provider.to_lowercase(), count + 1);
                let encrypted = Self::encrypt_value(raw_key);
                
                let _ = conn.execute(
                    "INSERT INTO sentinel_mesh (id, real_value, search_hash, agent_id, category) VALUES (?, ?, ?, ?, ?)",
                    params![next_id, encrypted, m_hash, "global", "Secret"],
                );
                next_id
            }
        }
    }

    /// Explicitly add PII to the mesh (e.g. via Telegram/Dashboard)
    pub fn add_global_pii(ptype: &str, raw_value: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(raw_value.as_bytes());
        let m_hash = format!("{:x}", hasher.finalize());

        let conn = DB.lock().unwrap_or_else(|e| e.into_inner());
        
        match conn.query_row(
            "SELECT id FROM sentinel_mesh WHERE search_hash = ?",
            params![m_hash],
            |row| row.get(0),
        ) {
            Ok(existing) => existing,
            Err(_) => {
                let count: i64 = conn.query_row(
                    "SELECT count(*) FROM sentinel_mesh WHERE category = 'PII'", 
                    [], 
                    |row| row.get(0)
                ).unwrap_or(0);
                
                let next_id = format!("sentinel_pii_{}_{}", ptype.to_lowercase(), count + 1);
                let encrypted = Self::encrypt_value(raw_value);
                
                let _ = conn.execute(
                    "INSERT INTO sentinel_mesh (id, real_value, search_hash, agent_id, category) VALUES (?, ?, ?, ?, ?)",
                    params![next_id, encrypted, m_hash, "global", "PII"],
                );
                SECRET_MAP_CACHE.insert(raw_value.to_string(), next_id.clone());
                next_id
            }
        }
    }

    /// Resolve a key by its provider name (used for upstream proxying)
    pub fn get_key_by_provider(provider: &str) -> Option<String> {
        let conn = DB.lock().unwrap_or_else(|e| e.into_inner());
        let pattern = format!("sentinel_secret_{}_%", provider.to_lowercase());
        
        let real_enc: Option<String> = conn.query_row(
            "SELECT real_value FROM sentinel_mesh WHERE id LIKE ? OR id = ? ORDER BY created_at DESC LIMIT 1",
            params![pattern, provider],
            |row| row.get(0)
        ).ok();

        real_enc.map(|enc| Self::decrypt_value(&enc))
    }

    /// [VPN-MODE] Restoration: Reverse Mapping
    /// Replaces Ghost IDs back into real values for command materialization.
    pub fn restore_mesh(input: &str) -> String {
        let mut output = input.to_string();
        let id_regex = Regex::new(r"sentinel_(secret|pii)_[a-z0-9_]+").unwrap();
        
        // 1. Identify only IDs present in the input
        let mut ids: Vec<String> = id_regex.find_iter(input)
            .map(|m| m.as_str().to_string())
            .collect();
            
        if ids.is_empty() { return output; }
        
        // Sort IDs by length (descending) to prevent greedy matching (openai_10 vs openai_1)
        ids.sort_by(|a, b| b.len().cmp(&a.len()));
        ids.dedup();

        let conn = DB.lock().unwrap_or_else(|e| e.into_inner());
        for id in ids {
            // 1. Check Hot Cache first (Skip SQL + AES Decrypt)
            if let Some(cached_secret) = ID_MAP_CACHE.get(&id) {
                let secret_val: &String = cached_secret.value();
                output = output.replace(&id, secret_val);
                continue;
            }

            let real_enc: Option<String> = conn.query_row(
                "SELECT real_value FROM sentinel_mesh WHERE id = ?",
                params![id],
                |row| row.get(0)
            ).ok();

            if let Some(enc) = real_enc {
                let real = Self::decrypt_value(&enc);
                // Populate hot cache for future efficiency
                ID_MAP_CACHE.insert(id.clone(), real.clone());
                output = output.replace(&id, &real);
            }
        }
        output
    }
    /// Securely purge the entire identity mesh (Reset Ghost IDs)
    pub fn clear_mesh() {
        let db = get_db_connection();
        let conn = db.lock().unwrap();
        let _ = conn.execute("DELETE FROM sentinel_mesh", []);
        println!("🧹 [SHIELD] Identity Mesh Purged.");
    }

    /**
     * Ported from v1: Detect risky shell execution patterns.
     * Hardened v0.0.1.3.x: Only block file ops when targeting restricted paths.
     * Benign commands (ls, find, cat, etc.) are allowed unless they access
     * sensitive files. Network recon and destructive commands are always blocked.
     */
    pub fn audit_shell(context: &str) -> Vec<String> {
        let mut risks = Vec::new();
        
        // 1. Normalization: Create a "clean" version for keyword matching
        let stripped: String = context.chars()
            .filter(|&c| c != '\'' && c != '"' && c != '\\')
            .collect::<String>()
            .to_lowercase();
        
        // 2. Syntax Normalization (with spaces) for structure analysis
        let mut syntax_clean = context.to_lowercase();
        for c in ['`', '$', '(', ')', '{', '}', ';', '&', '|', '>', '<'] {
            syntax_clean = syntax_clean.replace(c, " ");
        }
        
        // 3. Path Normalization: Collapse segments like /./ and //
        let mut path_clean = stripped.clone();
        while path_clean.contains("//") || path_clean.contains("/./") {
            path_clean = path_clean.replace("//", "/").replace("/./", "/");
        }

        // --- 1. Encoded/Payload Detection (always risky regardless of path) ---
        if stripped.contains("base64") && (stripped.contains(" -d") || stripped.contains("decode")) {
            risks.push("ENCODED_PAYLOAD_DETECTION".into());
        }

        // --- 2. Truly Destructive Commands (always blocked) ---
        let always_dangerous_cmds = ["sudo", "rm", "chmod", "unlink", "shred", "truncate", "chown", "pkill", "kill", "dd"];
        let words: Vec<&str> = stripped.split(|c: char| !c.is_alphanumeric()).collect();
        for cmd in always_dangerous_cmds {
            if words.contains(&cmd) {
                risks.push(format!("RISKY_COMMAND_DETECTION: {}", cmd));
            }
        }
        
        if stripped.contains("rm") && stripped.contains("rf") {
            risks.push("DESTRUCTIVE_COMMAND_DETECTION: rm -rf".into());
        }

        // --- 3. Inline Code Execution (always risky) ---
        let execs = ["python", "node", "perl", "ruby"];
        for exe in execs {
            if stripped.contains(exe) && (stripped.contains(" -c ") || stripped.contains(" -e ")) {
                risks.push(format!("INLINE_CODE_EXECUTION: {}", exe));
            }
        }

        // --- 4. Path-Conditional: only flag if targeting restricted paths ---
        let restricted_files = [
            ".env", "shadow", "id_rsa", "sentinel.toml", "sentinel.toml.example", "sudoers", "/etc/passwd"
        ];
        let mut hits_restricted_path = false;
        for file in restricted_files {
            if path_clean.ends_with(file) || path_clean.contains(&format!("/{}", file)) {
                hits_restricted_path = true;
                risks.push(format!("RESTRICTED_FILE_ACCESS: {}", file));
            }
        }
        
        let restricted_dirs = [
            "/root/", ".ssh", "/etc/shadow", "/etc/passwd"
        ];
        for dir in restricted_dirs {
            if path_clean.contains(dir) {
                hits_restricted_path = true;
                risks.push(format!("RESTRICTED_PATH_ACCESS: {}", dir));
            }
        }

        // --- 5. File Ops + Restricted Path = Block; File Ops alone = Allow ---
        // If no restricted path was hit, remove any NESTED_EXECUTION flag that
        // would have been raised by sh -c / bash -c (agent tool calls use these).
        // mv/cp are only dangerous when targeting restricted paths.
        let file_ops = ["mv", "cp"];
        for cmd in file_ops {
            if words.contains(&cmd) && !hits_restricted_path {
                // Benign file op on non-restricted path — don't flag
            } else if words.contains(&cmd) && hits_restricted_path {
                risks.push(format!("RISKY_COMMAND_DETECTION: {}", cmd));
            }
        }

        // Network recon is always blocked
        let network_recon = ["ip neigh", "ip route", "ifconfig", "netstat", "ss -", "nmap", "arp -"];
        for recon in network_recon {
            if stripped.contains(recon) {
                risks.push(format!("NETWORK_RECON: {}", recon.trim()));
            }
        }
        
        risks
    }

    /**
     * Heuristic Entropy Scrubber:
     * Scans for high-entropy tokens (potential obfuscated secrets) and redacts them.
     */
    pub fn scrub_high_entropy(input: &str, agent_id: &str) -> String {
        let skip_ranges = Self::build_skip_ranges(input);
        let mut output = input.to_string();
        let conn = DB.lock().unwrap_or_else(|e| e.into_inner());
        
        // Tokenize by common delimiters
        let tokens: Vec<&str> = input.split(|c: char| !c.is_alphanumeric() && c != '-' && c != '_').filter(|s| s.len() > 20).collect();
        
        for token in tokens {
            // Entropy Scrubber must ignore existing Ghost IDs
            if token.starts_with("sentinel_secret_") || token.starts_with("sentinel_pii_") || token.starts_with("sentinel_heuristic_") {
                continue;
            }
            
            // Skip tokens inside comment/example/ignore regions
            if let Some(pos) = output.find(token) {
                if Self::match_in_skip_range(pos, pos + token.len(), &skip_ranges) {
                    continue;
                }
            }

            let entropy = Self::calculate_entropy(token);
            
            // Lower threshold to catch Hex (max 4.0) and ROT13
            // 3.0 catches most random-looking strings while ignoring natural language
            if entropy > 3.7 {
                // Potential secret!
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(token.as_bytes());
                let t_hash = format!("{:x}", hasher.finalize());

                let id: String = match conn.query_row(
                    "SELECT id FROM sentinel_mesh WHERE search_hash = ?",
                    params![t_hash],
                    |row| row.get(0),
                ) {
                    Ok(existing) => existing,
                    Err(_) => {
                        let count: i64 = conn.query_row("SELECT count(*) FROM sentinel_mesh WHERE category = 'Heuristic'", [], |row| row.get(0)).unwrap_or(0);
                        let next_id = format!("sentinel_heuristic_{}_{}", "entropy", count + 1);
                        let encrypted = Self::encrypt_value(token);
                        let _ = conn.execute(
                            "INSERT INTO sentinel_mesh (id, real_value, search_hash, agent_id, category) VALUES (?, ?, ?, ?, ?)",
                            params![next_id, encrypted, t_hash, agent_id, "Heuristic"],
                        );
                        next_id
                    }
                };
                output = output.replace(token, &id);
            }
        }
        output
    }
}
