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

use serde::{Deserialize, Serialize};
use dashmap::DashMap;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MissionManifest {
    pub agent_id: String,
    pub task_goal: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SentinelDecision {
    pub approved: bool,
    pub reasoning: String,
    pub redacted_payload: Option<String>,
}

pub struct LanguageHarness {
    pub missions: DashMap<String, MissionManifest>,
}

impl LanguageHarness {
    pub fn new() -> Self {
        Self {
            missions: DashMap::new(),
        }
    }

    /**
     * Agent Registration:
     * Record the intent of the agent before allowing actions.
     */
    pub fn register_mission(&self, manifest: MissionManifest) {
        println!("📝 Registered New Mission: Agent {} is seeking to: {}", manifest.agent_id, manifest.task_goal);
        self.missions.insert(manifest.agent_id.clone(), manifest);
    }

    /// Audit proxy body: ONLY does secret detection & redaction.
    pub async fn audit_context(&self, context: &str, pii_enabled: bool, agent_id: &str) -> SentinelDecision {
        use crate::shield::SecretShield;
        use sha2::{Digest, Sha256};

        // 0. Cache Lookup: Skip heavy regex if we've seen this exact payload recently
        let mut hasher = Sha256::new();
        hasher.update(context.as_bytes());
        let ctx_hash = format!("{:x}", hasher.finalize());
        
        static AUDIT_CACHE: once_cell::sync::Lazy<DashMap<String, String>> = once_cell::sync::Lazy::new(DashMap::new);
        if let Some(cached) = AUDIT_CACHE.get(&ctx_hash) {
            return SentinelDecision {
                approved: true,
                reasoning: "✅ Sentinel Cache Hit (Verified Clean/Scrubbed)".to_string(),
                redacted_payload: if cached.as_str() == context { None } else { Some(cached.clone()) },
            };
        }

        let context_str = context.to_string();
        let agent_id_str = agent_id.to_string();

        // 1. Offload heavy regex scanning to a blocking thread
        let result = tokio::task::spawn_blocking(move || {
            let mut current_payload = context_str.clone();
            let mut modified = false;

            // Robust Normalization: Decode common obfuscation (Hex, URL, Unicode)
            let mut normalized = context_str.clone();
            
            // Handle URL encoding (e.g. %2D)
            if normalized.contains('%') {
                normalized = urlencoding::decode(&normalized).map(|d| d.into_owned()).unwrap_or_else(|_| normalized.clone());
            }
            
            // Handle Unicode escapes (e.g. \u002d)
            if normalized.contains("\\u") {
                normalized = normalized.replace("\\u002d", "-").replace("\\u002D", "-")
                                       .replace("\\u005f", "_").replace("\\u005F", "_")
                                       .replace("\\u003d", "=").replace("\\u003D", "=");
            }

            // 1. Secret Detection & Redaction (Lower entropy threshold for higher reliability)
            if SecretShield::is_known_secret_pattern(&normalized) || SecretShield::calculate_entropy(&normalized) > 4.0 {
                let scrubbed_secrets = SecretShield::scrub(&context_str, &agent_id_str);
                if scrubbed_secrets != context_str {
                    current_payload = scrubbed_secrets;
                    modified = true;
                }
            }

            // 2. [EXPERIMENTAL] PII Scrubbing
            if pii_enabled {
                let scrubbed_pii = SecretShield::scrub_pii(&current_payload, &agent_id_str);
                if scrubbed_pii != current_payload {
                    current_payload = scrubbed_pii;
                    modified = true;
                }
            }

            (current_payload, modified)
        }).await;

        match result {
            Ok((current_payload, modified)) => {
                // Populate Cache
                AUDIT_CACHE.insert(ctx_hash, current_payload.clone());
                if AUDIT_CACHE.len() > 1000 { AUDIT_CACHE.clear(); } // Simple TTL-like purge

                if modified {
                    crate::logger::log_event(
                        crate::logger::LogSource::Shield,
                        crate::logger::LogLevel::Secret,
                        "Shield: Sensitive pattern detected in payload. Redacting.",
                        None,
                    );
                }
                SentinelDecision {
                    approved: true,
                    reasoning: if modified { "🛡️ Sentinel Security Applied (Scrubbed)".to_string() } else { "✅ Payload Verified (Clean)".to_string() },
                    redacted_payload: if modified { Some(current_payload) } else { None },
                }
            }
            Err(_) => {
                SentinelDecision {
                    approved: false,
                    reasoning: "🛑 Shield Thread Panicked During Audit".to_string(),
                    redacted_payload: None,
                }
            }
        }
    }
}
