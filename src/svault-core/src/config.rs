use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::paths;

pub const CONFIG_FILE_NAME: &str = "broker.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct BrokerConfig {
    pub version: String,
    pub allowed_client_sids: Vec<String>,
    pub approval_ttl_seconds: i64,
    pub unlock_ttl_seconds: i64,
}

impl Default for BrokerConfig {
    fn default() -> Self {
        Self {
            version: "1.0.0".to_owned(),
            allowed_client_sids: Vec::new(),
            approval_ttl_seconds: 180,
            unlock_ttl_seconds: 300,
        }
    }
}

impl BrokerConfig {
    pub fn default_path() -> PathBuf {
        paths::config_file(&paths::home())
    }

    pub fn load(path: Option<&Path>) -> Self {
        let file = path.map(Path::to_path_buf).unwrap_or_else(Self::default_path);
        let Ok(contents) = fs::read_to_string(&file) else {
            return Self::default();
        };
        // Strip optional UTF-8 BOM written by Windows PowerShell Set-Content -Encoding UTF8.
        let cleaned = contents.strip_prefix('\u{feff}').unwrap_or(&contents);
        serde_json::from_str(cleaned).unwrap_or_default()
    }
}
