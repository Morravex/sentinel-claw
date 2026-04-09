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
use serde::Deserialize;
use config::{Config, ConfigError, File, Environment};

#[derive(Debug, Deserialize, Clone)]
pub struct SentinelConfig {
    pub general: GeneralConfig,
    pub local: LocalConfig,
    pub cloud: CloudConfig,
    pub providers: HashMap<String, String>,
    pub agents: HashMap<String, u16>,
    pub policy: PolicyConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct GeneralConfig {
    pub mode: String,
    pub socket_path: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LocalConfig {
    pub model: String,
    pub host: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CloudConfig {
    pub provider: String,
    pub base_url: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PolicyConfig {
    pub pii_redaction: bool,
    pub deny_list: Vec<String>,
    pub restricted_paths: Vec<String>,
}

impl SentinelConfig {
    pub fn load() -> Result<Self, ConfigError> {
        Self::load_from("sentinel.toml").or_else(|_| Self::load_from("sentinel.toml.example"))
    }

    pub fn load_from(path: &str) -> Result<Self, ConfigError> {
        let s = Config::builder()
            .add_source(File::with_name(path))
            .add_source(Environment::with_prefix("SENTINEL"))
            .build()?;
        s.try_deserialize()
    }
}
