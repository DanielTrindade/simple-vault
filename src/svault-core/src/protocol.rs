use std::collections::BTreeMap;
use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};

pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

pub mod error_codes {
    pub const BAD_REQUEST: &str = "bad_request";
    pub const UNAUTHORIZED: &str = "unauthorized";
    pub const PASSPHRASE_REQUIRED: &str = "passphrase_required";
    pub const PASSPHRASE_INVALID: &str = "passphrase_invalid";
    pub const TOTP_REQUIRED: &str = "totp_required";
    pub const TOTP_INVALID: &str = "totp_invalid";
    pub const NOT_FOUND: &str = "not_found";
    pub const NOT_AUTHORIZED: &str = "not_authorized";
    pub const TARGET_NOT_ALLOWED: &str = "target_not_allowed";
    pub const CONFLICT: &str = "conflict";
    pub const EXPIRED: &str = "expired";
    pub const EXECUTION_FAILED: &str = "execution_failed";
    pub const VAULT_NOT_INITIALIZED: &str = "vault_not_initialized";
    pub const INTERNAL: &str = "internal_error";
}

pub mod operation_statuses {
    pub const PENDING_APPROVAL: &str = "pending_approval";
    pub const APPROVED: &str = "approved";
    pub const RUNNING: &str = "running";
    pub const COMPLETED: &str = "completed";
    pub const FAILED: &str = "failed";
    pub const REJECTED: &str = "rejected";
    pub const EXPIRED: &str = "expired";
    pub const REVOKED: &str = "revoked";
}

pub mod approval_requirements {
    pub const PASSPHRASE: &str = "passphrase";
    pub const PASSPHRASE_AND_TOTP: &str = "passphrase+totp";
    pub const NONE: &str = "none";
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Envelope {
    pub cmd: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EnvelopeResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorPayload>,
}

impl EnvelopeResponse {
    pub fn success<T: Serialize>(data: T) -> Self {
        match serde_json::to_value(data) {
            Ok(val) => Self {
                ok: true,
                data: Some(val),
                error: None,
            },
            Err(_) => Self::failure(error_codes::INTERNAL, "Falha ao serializar resposta."),
        }
    }

    pub fn failure(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            data: None,
            error: Some(ErrorPayload {
                code: code.into(),
                message: message.into(),
            }),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ErrorPayload {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct HealthInfo {
    pub status: String,
    pub version: String,
    pub service_identity: String,
    pub vault_initialized: bool,
    pub totp_required: bool,
    pub state_path: String,
    pub entry_count: i32,
    pub operation_count: i32,
}

impl Default for HealthInfo {
    fn default() -> Self {
        Self {
            status: "ok".to_owned(),
            version: "1.0.0".to_owned(),
            service_identity: String::new(),
            vault_initialized: false,
            totp_required: false,
            state_path: String::new(),
            entry_count: 0,
            operation_count: 0,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EntryMetadata {
    pub id: String,
    pub kind: String,
    pub label: String,
    pub targets: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
    pub revision: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct OperationMetadata {
    pub id: String,
    pub entry_id: String,
    pub action: String,
    pub target: String,
    pub requires_approval: bool,
    pub description: String,
    pub params: Vec<String>,
}

impl Default for OperationMetadata {
    fn default() -> Self {
        Self {
            id: String::new(),
            entry_id: String::new(),
            action: String::new(),
            target: String::new(),
            requires_approval: true,
            description: String::new(),
            params: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct OperationSummary {
    pub operation_id: String,
    pub entry_id: String,
    pub action: String,
    pub target: String,
    pub requires_approval: bool,
    pub description: String,
    pub parameters: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    pub referenced_entries: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct OperationRequestResult {
    pub request_id: String,
    pub status: String,
    pub requires: String,
    pub expires_at: String,
    pub summary: OperationSummary,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct OperationStatusResult {
    pub request_id: String,
    pub status: String,
    pub summary: OperationSummary,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<OperationOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct OperationOutcome {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<i32>,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    pub duration_ms: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PendingRequest {
    pub request_id: String,
    pub created_at: String,
    pub expires_at: String,
    pub summary: OperationSummary,
}

pub fn write_frame(stream: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    let length = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Tamanho de mensagem invalido."))?;
    stream.write_all(&length.to_le_bytes())?;
    stream.write_all(payload)?;
    stream.flush()
}

pub fn read_frame(stream: &mut impl Read, max_bytes: usize) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    let length = i32::from_le_bytes(header);
    if length <= 0 || length as usize > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Tamanho de mensagem invalido.",
        ));
    }
    let mut payload = vec![0u8; length as usize];
    stream.read_exact(&mut payload)?;
    Ok(payload)
}
