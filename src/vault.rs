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

use std::collections::HashMap;
use std::sync::Arc;
use dashmap::DashMap;

#[derive(Clone)]
pub struct SentinelVault {
    pub agents: Arc<DashMap<String, HashMap<String, String>>>,
    pub global: Arc<HashMap<String, String>>,
}

impl SentinelVault {
    pub fn new() -> Self {
        // Load .env before reading env vars
        dotenv::dotenv().ok();
        let mut global = HashMap::new();
        for (k, v) in std::env::vars() {
            global.insert(k, v);
        }

        Self {
            agents: Arc::new(DashMap::new()),
            global: Arc::new(global),
        }
    }

    pub fn get_key(&self, agent_id: &str, provider: &str) -> Option<String> {
        // 1. Try agent-specific key (e.g. from .env-openclaw)
        if let Some(agent_keys) = self.agents.get(agent_id) {
            if let Some(key) = agent_keys.get(provider) {
                return Some(key.clone());
            }
            let env_name = format!("{}_API_KEY", provider.to_uppercase());
            if let Some(key) = agent_keys.get(&env_name) {
                return Some(key.clone());
            }
        }

        // 2. Fallback to static global env vars
        let env_name = format!("{}_API_KEY", provider.to_uppercase());
        if let Some(key) = self.global.get(&env_name) {
            return Some(key.clone());
        }

        // 3. Final Fallback: Check the encrypted SQL mesh (keys added via Telegram/Dashboard)
        use crate::shield::SecretShield;
        SecretShield::get_key_by_provider(provider)
    }

    pub fn load_agent_env(&self, agent_id: &str, path: &str) {
        if let Ok(content) = std::fs::read_to_string(path) {
            let mut keys = HashMap::new();
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') { continue; }
                if let Some((k, v)) = line.split_once('=') {
                    keys.insert(k.trim().to_string(), v.trim().trim_matches('"').trim_matches('\'').to_string());
                }
            }
            self.agents.insert(agent_id.to_string(), keys);
        }
    }
}
