use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

fn default_version() -> i32 {
    1
}

fn default_kind() -> String {
    "generic".to_owned()
}

fn default_revision() -> i32 {
    1
}

fn default_true() -> bool {
    true
}

fn default_method() -> String {
    "POST".to_owned()
}

fn default_content_type() -> String {
    "application/json".to_owned()
}

fn default_timeout() -> i32 {
    30
}

/// Non-secret vault metadata. Secret values never live in this file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VaultState {
    #[serde(default = "default_version")]
    pub version: i32,
    pub initialized: bool,
    pub master_salt: String,
    pub key_check: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_generation: Option<String>,
    pub totp_enabled: bool,
    pub totp_secret: String,
    pub entries: Vec<EntryRecord>,
    pub operations: Vec<OperationRecord>,
    pub known_credential_targets: Vec<String>,
}

impl Default for VaultState {
    fn default() -> Self {
        Self {
            version: 1,
            initialized: false,
            master_salt: String::new(),
            key_check: String::new(),
            credential_generation: None,
            totp_enabled: false,
            totp_secret: String::new(),
            entries: Vec::new(),
            operations: Vec::new(),
            known_credential_targets: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EntryRecord {
    pub identity_id: String,
    pub id: String,
    #[serde(default = "default_kind")]
    pub kind: String,
    pub label: String,
    pub targets: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default = "default_revision")]
    pub revision: i32,
    pub entry_salt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_version: Option<String>,
}

impl Default for EntryRecord {
    fn default() -> Self {
        Self {
            identity_id: String::new(),
            id: String::new(),
            kind: "generic".to_owned(),
            label: String::new(),
            targets: Vec::new(),
            created_at: String::new(),
            updated_at: String::new(),
            revision: 1,
            entry_salt: String::new(),
            credential_version: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct OperationRecord {
    pub authorization_id: String,
    pub id: String,
    pub entry_id: String,
    pub action: String,
    pub target: String,
    #[serde(default = "default_true")]
    pub requires_approval: bool,
    pub description: String,
    pub params: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpRequestRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessRecord>,
}

impl Default for OperationRecord {
    fn default() -> Self {
        Self {
            authorization_id: String::new(),
            id: String::new(),
            entry_id: String::new(),
            action: String::new(),
            target: String::new(),
            requires_approval: true,
            description: String::new(),
            params: Vec::new(),
            http: None,
            process: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct HttpRequestRecord {
    #[serde(default = "default_method")]
    pub method: String,
    pub url: String,
    #[serde(default = "default_content_type")]
    pub content_type: String,
    pub body_fields: BTreeMap<String, String>,
    pub headers: BTreeMap<String, String>,
    pub result_fields: Vec<String>,
}

impl Default for HttpRequestRecord {
    fn default() -> Self {
        Self {
            method: "POST".to_owned(),
            url: String::new(),
            content_type: "application/json".to_owned(),
            body_fields: BTreeMap::new(),
            headers: BTreeMap::new(),
            result_fields: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ProcessRecord {
    pub executable: String,
    pub args: Vec<String>,
    pub env: Vec<String>,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: i32,
}

impl Default for ProcessRecord {
    fn default() -> Self {
        Self {
            executable: String::new(),
            args: Vec::new(),
            env: Vec::new(),
            timeout_seconds: 30,
        }
    }
}
