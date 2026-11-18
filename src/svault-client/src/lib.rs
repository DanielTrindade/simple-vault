pub mod secure_input;

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io;
use std::thread;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub use svault_core::paths::{ENV_PIPE, PIPE_NAME as DEFAULT_PIPE};
pub use svault_core::protocol::{
    EntryMetadata, Envelope, EnvelopeResponse, ErrorPayload, HealthInfo, MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES, OperationMetadata, OperationOutcome, OperationRequestResult,
    OperationStatusResult, OperationSummary, PendingRequest, error_codes, operation_statuses,
    read_frame, write_frame,
};

const ERROR_PIPE_BUSY: i32 = 231;
const ERROR_PIPE_NOT_CONNECTED: i32 = 233;

#[derive(Debug, Clone)]
pub struct BrokerError {
    pub code: String,
    pub message: String,
}

impl BrokerError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn is_unavailable(&self) -> bool {
        self.code == "unavailable"
    }
}

impl fmt::Display for BrokerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for BrokerError {}

pub type Result<T> = std::result::Result<T, BrokerError>;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EntryList {
    pub entries: Vec<EntryMetadata>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct OperationList {
    pub operations: Vec<OperationMetadata>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PendingList {
    pub requests: Vec<PendingRequest>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct OkResult {
    pub ok: bool,
    pub request_id: Option<String>,
    pub status: Option<String>,
    pub deleted: bool,
    pub revoked: bool,
    pub changed: bool,
    pub totp_enabled: bool,
    pub initialized: bool,
    pub reset: bool,
    pub entries_removed: i32,
    pub totp_uri: Option<String>,
    pub result: Option<OperationOutcome>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct HttpSpec {
    pub method: String,
    pub url: String,
    pub content_type: String,
    pub body_fields: BTreeMap<String, String>,
    pub headers: BTreeMap<String, String>,
    pub result_fields: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ProcessSpec {
    pub executable: String,
    pub args: Vec<String>,
    pub env: Vec<String>,
    pub timeout_seconds: i32,
}

#[derive(Debug, Clone, Default)]
pub struct AuthorizeRequest {
    pub id: String,
    pub entry_id: String,
    pub action: String,
    pub target: String,
    pub description: String,
    pub params: Vec<String>,
    pub http: Option<HttpSpec>,
    pub process: Option<ProcessSpec>,
}

#[derive(Clone, Debug)]
pub struct BrokerClient {
    path: String,
}

impl Default for BrokerClient {
    fn default() -> Self {
        Self::from_env()
    }
}

impl BrokerClient {
    pub fn from_env() -> Self {
        let name = std::env::var(ENV_PIPE)
            .ok()
            .filter(|v| !v.trim().is_empty());
        Self::new(name.as_deref().unwrap_or(DEFAULT_PIPE))
    }

    pub fn new(pipe: &str) -> Self {
        Self {
            path: svault_core::paths::pipe_path(pipe),
        }
    }

    pub fn pipe_path(&self) -> &str {
        &self.path
    }

    pub fn send<B: Serialize, T: DeserializeOwned>(&self, cmd: &str, body: Option<&B>) -> Result<T> {
        let request = encode_request(cmd, body)?;
        let response = self.exchange(&request)?;
        decode_response(&response)
    }

    pub fn send_raw<B: Serialize>(&self, cmd: &str, body: Option<&B>) -> Result<serde_json::Value> {
        self.send(cmd, body)
    }

    pub fn health(&self) -> Result<HealthInfo> {
        self.send::<(), _>("health", None)
    }

    pub fn list_entries(&self) -> Result<Vec<EntryMetadata>> {
        Ok(self.send::<(), EntryList>("list_entries", None)?.entries)
    }

    pub fn list_operations(&self) -> Result<Vec<OperationMetadata>> {
        Ok(self
            .send::<(), OperationList>("list_operations", None)?
            .operations)
    }

    pub fn pending_approvals(&self) -> Result<Vec<PendingRequest>> {
        Ok(self
            .send::<(), PendingList>("pending_approvals", None)?
            .requests)
    }

    pub fn request_operation(
        &self,
        op_id: &str,
        parameters: Option<&BTreeMap<String, String>>,
    ) -> Result<OperationRequestResult> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            op_id: &'a str,
            params: BTreeMap<&'a str, &'a str>,
        }
        let params = parameters
            .map(|m| m.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect())
            .unwrap_or_default();
        self.send("request_operation", Some(&Body { op_id, params }))
    }

    pub fn operation_status(&self, request_id: &str) -> Result<OperationStatusResult> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            request_id: &'a str,
        }
        self.send("operation_status", Some(&Body { request_id }))
    }

    pub fn init_vault(&self, passphrase: &str, enable_totp: bool) -> Result<OkResult> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            passphrase: &'a str,
            enable_totp: bool,
        }
        self.send(
            "init_vault",
            Some(&Body {
                passphrase,
                enable_totp,
            }),
        )
    }

    pub fn register_entry(
        &self,
        id: &str,
        kind: &str,
        label: &str,
        targets: &[String],
        value: &str,
        passphrase: &str,
    ) -> Result<EntryMetadata> {
        #[derive(Serialize)]
        struct Body<'a> {
            id: &'a str,
            kind: &'a str,
            label: &'a str,
            targets: &'a [String],
            value: &'a str,
            passphrase: &'a str,
        }
        self.send(
            "register_entry",
            Some(&Body {
                id,
                kind,
                label,
                targets,
                value,
                passphrase,
            }),
        )
    }

    pub fn update_entry(
        &self,
        id: &str,
        value: Option<&str>,
        label: Option<&str>,
        targets: Option<&[String]>,
        passphrase: &str,
    ) -> Result<EntryMetadata> {
        #[derive(Serialize)]
        struct Body<'a> {
            id: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            value: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            label: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            targets: Option<&'a [String]>,
            passphrase: &'a str,
        }
        self.send(
            "update_entry",
            Some(&Body {
                id,
                value,
                label,
                targets,
                passphrase,
            }),
        )
    }

    pub fn delete_entry(&self, id: &str, passphrase: &str) -> Result<OkResult> {
        self.send("delete_entry", Some(&IdBody { id, passphrase }))
    }

    pub fn authorize_operation(
        &self,
        request: &AuthorizeRequest,
        passphrase: &str,
    ) -> Result<OperationMetadata> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            id: &'a str,
            entry_id: &'a str,
            action: &'a str,
            target: &'a str,
            description: &'a str,
            params: &'a [String],
            passphrase: &'a str,
            #[serde(flatten, skip_serializing_if = "Option::is_none")]
            http: Option<&'a HttpSpec>,
            #[serde(flatten, skip_serializing_if = "Option::is_none")]
            process: Option<&'a ProcessSpec>,
        }
        self.send(
            "authorize_operation",
            Some(&Body {
                id: &request.id,
                entry_id: &request.entry_id,
                action: &request.action,
                target: &request.target,
                description: &request.description,
                params: &request.params,
                passphrase,
                http: request.http.as_ref(),
                process: request.process.as_ref(),
            }),
        )
    }

    pub fn revoke_operation(&self, id: &str, passphrase: &str) -> Result<OkResult> {
        self.send("revoke_operation", Some(&IdBody { id, passphrase }))
    }

    pub fn approve(
        &self,
        request_id: &str,
        passphrase: &str,
        totp: Option<&str>,
    ) -> Result<OkResult> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            request_id: &'a str,
            passphrase: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            totp: Option<&'a str>,
        }
        self.send(
            "approve",
            Some(&Body {
                request_id,
                passphrase,
                totp,
            }),
        )
    }

    pub fn reject(&self, request_id: &str, passphrase: &str) -> Result<OkResult> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            request_id: &'a str,
            passphrase: &'a str,
        }
        self.send(
            "reject",
            Some(&Body {
                request_id,
                passphrase,
            }),
        )
    }

    pub fn set_totp(
        &self,
        secret: &str,
        passphrase: &str,
        totp: Option<&str>,
    ) -> Result<OkResult> {
        #[derive(Serialize)]
        struct Body<'a> {
            secret: &'a str,
            passphrase: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            totp: Option<&'a str>,
        }
        self.send(
            "set_totp",
            Some(&Body {
                secret,
                passphrase,
                totp,
            }),
        )
    }

    pub fn disable_totp(&self, passphrase: &str, totp: Option<&str>) -> Result<OkResult> {
        #[derive(Serialize)]
        struct Body<'a> {
            passphrase: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            totp: Option<&'a str>,
        }
        self.send("disable_totp", Some(&Body { passphrase, totp }))
    }

    pub fn change_passphrase(
        &self,
        current: &str,
        next: &str,
        totp: Option<&str>,
    ) -> Result<OkResult> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            current_passphrase: &'a str,
            new_passphrase: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            totp: Option<&'a str>,
        }
        self.send(
            "change_passphrase",
            Some(&Body {
                current_passphrase: current,
                new_passphrase: next,
                totp,
            }),
        )
    }

    pub fn reset_vault(&self, passphrase: &str, totp: Option<&str>) -> Result<OkResult> {
        #[derive(Serialize)]
        struct Body<'a> {
            passphrase: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            totp: Option<&'a str>,
        }
        self.send("reset_vault", Some(&Body { passphrase, totp }))
    }

    fn exchange(&self, request: &[u8]) -> Result<Vec<u8>> {
        let mut attempt = 0;
        loop {
            attempt += 1;
            let step = (|| -> io::Result<Vec<u8>> {
                let mut pipe = self.open_once()?;
                write_frame(&mut pipe, request)?;
                read_frame(&mut pipe, MAX_RESPONSE_BYTES)
            })();

            match step {
                Ok(bytes) => return Ok(bytes),
                Err(err)
                    if attempt < 4
                        && (matches!(
                            err.raw_os_error(),
                            Some(ERROR_PIPE_BUSY | ERROR_PIPE_NOT_CONNECTED)
                        ) || matches!(
                            err.kind(),
                            io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
                        )) =>
                {
                    thread::sleep(Duration::from_millis(150));
                }
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    return Err(BrokerError::new(
                        "unavailable",
                        "Broker indisponível: o serviço SVaultBroker não está em execução.",
                    ));
                }
                Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
                    return Err(BrokerError::new(
                        "unavailable",
                        "Acesso ao broker negado para este usuário.",
                    ));
                }
                Err(err) => return Err(io_error(err)),
            }
        }
    }

    fn open_once(&self) -> io::Result<File> {
        OpenOptions::new().read(true).write(true).open(&self.path)
    }
}

#[derive(Serialize)]
struct IdBody<'a> {
    id: &'a str,
    passphrase: &'a str,
}

#[derive(Serialize)]
struct OutboundEnvelope<'a, B: Serialize> {
    cmd: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<&'a B>,
}

fn io_error(err: io::Error) -> BrokerError {
    BrokerError::new(
        "unavailable",
        format!("Falha na comunicação com o broker: {err}"),
    )
}

pub fn encode_request<B: Serialize>(cmd: &str, body: Option<&B>) -> Result<Zeroizing<Vec<u8>>> {
    // Pre-sized so serde never reallocates: a reallocation would leave a stray copy of the
    // passphrase in freed heap memory that zeroize can no longer reach.
    let mut buffer = Zeroizing::new(Vec::with_capacity(MAX_REQUEST_BYTES));
    serde_json::to_writer(&mut *buffer, &OutboundEnvelope { cmd, body })
        .map_err(|e| BrokerError::new("bad_request", format!("Falha ao montar a requisição: {e}")))?;
    if buffer.len() > MAX_REQUEST_BYTES {
        return Err(BrokerError::new(
            "bad_request",
            "Requisição maior que o limite aceito pelo broker.",
        ));
    }
    Ok(buffer)
}

pub fn decode_response<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let envelope: EnvelopeResponse = serde_json::from_slice(bytes)
        .map_err(|_| BrokerError::new("internal_error", "Resposta inválida do broker."))?;

    if !envelope.ok {
        let error = envelope.error.unwrap_or(ErrorPayload {
            code: "internal_error".to_owned(),
            message: "Erro desconhecido.".to_owned(),
        });
        let code = if error.code.is_empty() {
            "internal_error"
        } else {
            error.code.as_str()
        };
        let message = if error.message.is_empty() {
            "Erro desconhecido.".to_owned()
        } else {
            error.message
        };
        return Err(BrokerError::new(code, message));
    }

    let data = envelope.data.unwrap_or(serde_json::Value::Null);
    serde_json::from_value(data)
        .map_err(|_| BrokerError::new("internal_error", "Resposta sem o conteúdo esperado."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn frame_round_trip_uses_little_endian_length() {
        let mut buffer = Vec::new();
        write_frame(&mut buffer, b"{\"cmd\":\"health\"}").unwrap();
        assert_eq!(&buffer[..4], &16u32.to_le_bytes());
        let payload = read_frame(&mut Cursor::new(buffer), MAX_RESPONSE_BYTES).unwrap();
        assert_eq!(payload, b"{\"cmd\":\"health\"}");
    }

    #[test]
    fn read_frame_rejects_oversized_and_empty_lengths() {
        let oversized = [
            (MAX_RESPONSE_BYTES as u32 + 1).to_le_bytes().to_vec(),
            vec![0; 8],
        ]
        .concat();
        assert!(read_frame(&mut Cursor::new(oversized), MAX_RESPONSE_BYTES).is_err());
        assert!(read_frame(&mut Cursor::new(0u32.to_le_bytes().to_vec()), MAX_RESPONSE_BYTES).is_err());
    }

    #[test]
    fn envelope_without_body_matches_broker_contract() {
        let bytes = encode_request::<()>("health", None).unwrap();
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), r#"{"cmd":"health"}"#);
    }

    #[test]
    fn broker_errors_keep_code_and_message() {
        let raw = br#"{"ok":false,"error":{"code":"passphrase_invalid","message":"Senha do cofre incorreta."}}"#;
        let err = decode_response::<OkResult>(raw).unwrap_err();
        assert_eq!(err.code, "passphrase_invalid");
        assert_eq!(err.message, "Senha do cofre incorreta.");
    }
}
