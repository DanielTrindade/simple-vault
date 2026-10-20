use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::thread;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const DEFAULT_PIPE: &str = "svault.broker.v1";
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

const ERROR_PIPE_BUSY: i32 = 231;

#[derive(Debug, Clone)]
pub struct BrokerError {
    pub code: String,
    pub message: String,
}

impl BrokerError {
    fn new(code: &str, message: impl Into<String>) -> Self {
        Self { code: code.to_owned(), message: message.into() }
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

pub type Result<T> = std::result::Result<T, BrokerError>;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Health {
    pub status: String,
    pub version: String,
    pub service_identity: String,
    pub vault_initialized: bool,
    pub totp_required: bool,
    pub entry_count: i32,
    pub operation_count: i32,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Entry {
    pub id: String,
    pub kind: String,
    pub label: String,
    pub targets: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
    pub revision: i32,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Operation {
    pub id: String,
    pub entry_id: String,
    pub action: String,
    pub target: String,
    pub requires_approval: bool,
    pub description: String,
    pub params: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Summary {
    pub operation_id: String,
    pub entry_id: String,
    pub action: String,
    pub target: String,
    pub requires_approval: bool,
    pub description: String,
    pub parameters: BTreeMap<String, String>,
    pub method: Option<String>,
    pub referenced_entries: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PendingRequest {
    pub request_id: String,
    pub created_at: String,
    pub expires_at: String,
    pub summary: Summary,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Outcome {
    pub kind: String,
    pub status_code: Option<i32>,
    pub ok: bool,
    pub body: Option<String>,
    pub output: Option<String>,
    pub exit_code: Option<i32>,
    pub duration_ms: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct OkResult {
    pub status: Option<String>,
    pub totp_uri: Option<String>,
    pub result: Option<Outcome>,
    pub error: Option<String>,
}

#[derive(Deserialize)]
struct EntryList {
    #[serde(default)]
    entries: Vec<Entry>,
}

#[derive(Deserialize)]
struct OperationList {
    #[serde(default)]
    operations: Vec<Operation>,
}

#[derive(Deserialize)]
struct PendingList {
    #[serde(default)]
    requests: Vec<PendingRequest>,
}

#[derive(Serialize)]
struct Envelope<'a, B: Serialize> {
    cmd: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<&'a B>,
}

#[derive(Deserialize)]
struct EnvelopeResponse {
    ok: bool,
    data: Option<serde_json::Value>,
    error: Option<ErrorPayload>,
}

#[derive(Deserialize)]
struct ErrorPayload {
    code: Option<String>,
    message: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpSpec {
    pub method: String,
    pub url: String,
    pub content_type: String,
    pub body_fields: BTreeMap<String, String>,
    pub headers: BTreeMap<String, String>,
    pub result_fields: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
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

#[derive(Clone)]
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
        let name = std::env::var("SVAULT_PIPE").ok().filter(|v| !v.trim().is_empty());
        Self::new(name.as_deref().unwrap_or(DEFAULT_PIPE))
    }

    pub fn new(pipe: &str) -> Self {
        let pipe = pipe.trim();
        let path = if pipe.starts_with(r"\\") { pipe.to_owned() } else { format!(r"\\.\pipe\{pipe}") };
        Self { path }
    }

    pub fn health(&self) -> Result<Health> {
        self.send::<(), _>("health", None)
    }

    pub fn list_entries(&self) -> Result<Vec<Entry>> {
        Ok(self.send::<(), EntryList>("list_entries", None)?.entries)
    }

    pub fn list_operations(&self) -> Result<Vec<Operation>> {
        Ok(self.send::<(), OperationList>("list_operations", None)?.operations)
    }

    pub fn pending_approvals(&self) -> Result<Vec<PendingRequest>> {
        Ok(self.send::<(), PendingList>("pending_approvals", None)?.requests)
    }

    pub fn init_vault(&self, passphrase: &str, enable_totp: bool) -> Result<OkResult> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            passphrase: &'a str,
            enable_totp: bool,
        }
        self.send("init_vault", Some(&Body { passphrase, enable_totp }))
    }

    pub fn register_entry(
        &self,
        id: &str,
        kind: &str,
        label: &str,
        targets: &[String],
        value: &str,
        passphrase: &str,
    ) -> Result<Entry> {
        #[derive(Serialize)]
        struct Body<'a> {
            id: &'a str,
            kind: &'a str,
            label: &'a str,
            targets: &'a [String],
            value: &'a str,
            passphrase: &'a str,
        }
        self.send("register_entry", Some(&Body { id, kind, label, targets, value, passphrase }))
    }

    pub fn update_entry(
        &self,
        id: &str,
        label: Option<&str>,
        targets: &[String],
        value: Option<&str>,
        passphrase: &str,
    ) -> Result<Entry> {
        #[derive(Serialize)]
        struct Body<'a> {
            id: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            label: Option<&'a str>,
            targets: &'a [String],
            #[serde(skip_serializing_if = "Option::is_none")]
            value: Option<&'a str>,
            passphrase: &'a str,
        }
        self.send("update_entry", Some(&Body { id, label, targets, value, passphrase }))
    }

    pub fn delete_entry(&self, id: &str, passphrase: &str) -> Result<OkResult> {
        self.send("delete_entry", Some(&IdBody { id, passphrase }))
    }

    pub fn authorize_operation(&self, request: &AuthorizeRequest, passphrase: &str) -> Result<Operation> {
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

    pub fn approve(&self, request_id: &str, passphrase: &str, totp: Option<&str>) -> Result<OkResult> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            request_id: &'a str,
            passphrase: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            totp: Option<&'a str>,
        }
        self.send("approve", Some(&Body { request_id, passphrase, totp }))
    }

    pub fn reject(&self, request_id: &str, passphrase: &str) -> Result<OkResult> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            request_id: &'a str,
            passphrase: &'a str,
        }
        self.send("reject", Some(&Body { request_id, passphrase }))
    }

    fn send<B: Serialize, T: DeserializeOwned>(&self, cmd: &str, body: Option<&B>) -> Result<T> {
        let request = encode_request(cmd, body)?;
        let response = self.exchange(&request)?;
        decode_response(&response)
    }

    fn exchange(&self, request: &[u8]) -> Result<Vec<u8>> {
        let mut pipe = self.connect()?;
        write_frame(&mut pipe, request).map_err(io_error)?;
        read_frame(&mut pipe, MAX_RESPONSE_BYTES).map_err(io_error)
    }

    fn connect(&self) -> Result<File> {
        let mut attempt = 0;
        loop {
            attempt += 1;
            match OpenOptions::new().read(true).write(true).open(&self.path) {
                Ok(file) => return Ok(file),
                Err(err) if attempt < 4 && err.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                    thread::sleep(Duration::from_millis(150));
                }
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    return Err(BrokerError::new(
                        "unavailable",
                        "Broker indisponível: o serviço SVaultBroker não está em execução.",
                    ));
                }
                Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
                    return Err(BrokerError::new("unavailable", "Acesso ao broker negado para este usuário."));
                }
                Err(err) => return Err(io_error(err)),
            }
        }
    }
}

#[derive(Serialize)]
struct IdBody<'a> {
    id: &'a str,
    passphrase: &'a str,
}

fn io_error(err: io::Error) -> BrokerError {
    BrokerError::new("unavailable", format!("Falha na comunicação com o broker: {err}"))
}

pub fn encode_request<B: Serialize>(cmd: &str, body: Option<&B>) -> Result<Zeroizing<Vec<u8>>> {
    // Pre-sized so serde never reallocates: a reallocation would leave a stray copy of the
    // passphrase in freed heap memory that zeroize can no longer reach.
    let mut buffer = Zeroizing::new(Vec::with_capacity(MAX_REQUEST_BYTES));
    serde_json::to_writer(&mut *buffer, &Envelope { cmd, body })
        .map_err(|e| BrokerError::new("bad_request", format!("Falha ao montar a requisição: {e}")))?;
    if buffer.len() > MAX_REQUEST_BYTES {
        return Err(BrokerError::new("bad_request", "Requisição maior que o limite aceito pelo broker."));
    }
    Ok(buffer)
}

pub fn decode_response<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let envelope: EnvelopeResponse = serde_json::from_slice(bytes)
        .map_err(|_| BrokerError::new("internal_error", "Resposta inválida do broker."))?;

    if !envelope.ok {
        let error = envelope.error.unwrap_or(ErrorPayload { code: None, message: None });
        return Err(BrokerError::new(
            error.code.as_deref().unwrap_or("internal_error"),
            error.message.unwrap_or_else(|| "Erro desconhecido.".to_owned()),
        ));
    }

    let data = envelope.data.unwrap_or(serde_json::Value::Null);
    serde_json::from_value(data).map_err(|_| BrokerError::new("internal_error", "Resposta sem o conteúdo esperado."))
}

pub fn write_frame(stream: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    let length = u32::try_from(payload.len()).map_err(|_| io::Error::other("mensagem grande demais"))?;
    stream.write_all(&length.to_le_bytes())?;
    stream.write_all(payload)?;
    stream.flush()
}

pub fn read_frame(stream: &mut impl Read, max_bytes: usize) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    let length = i32::from_le_bytes(header);
    if length <= 0 || length as usize > max_bytes {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "tamanho de mensagem inválido"));
    }
    let mut payload = vec![0u8; length as usize];
    stream.read_exact(&mut payload)?;
    Ok(payload)
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
        let oversized = [(MAX_RESPONSE_BYTES as u32 + 1).to_le_bytes().to_vec(), vec![0; 8]].concat();
        assert!(read_frame(&mut Cursor::new(oversized), MAX_RESPONSE_BYTES).is_err());
        assert!(read_frame(&mut Cursor::new(0u32.to_le_bytes().to_vec()), MAX_RESPONSE_BYTES).is_err());
    }

    #[test]
    fn envelope_without_body_matches_broker_contract() {
        let bytes = encode_request::<()>("health", None).unwrap();
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), r#"{"cmd":"health"}"#);
    }

    #[test]
    fn authorize_body_flattens_http_spec_in_camel_case() {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Probe<'a> {
            entry_id: &'a str,
            #[serde(flatten)]
            http: &'a HttpSpec,
        }
        let spec = HttpSpec { method: "POST".into(), content_type: "application/json".into(), ..Default::default() };
        let json = serde_json::to_value(Probe { entry_id: "SENHA", http: &spec }).unwrap();
        assert_eq!(json["entryId"], "SENHA");
        assert_eq!(json["contentType"], "application/json");
        assert!(json.get("bodyFields").is_some());
    }

    #[test]
    fn broker_errors_keep_code_and_message() {
        let raw = br#"{"ok":false,"error":{"code":"passphrase_invalid","message":"Senha do cofre incorreta."}}"#;
        let err = decode_response::<OkResult>(raw).unwrap_err();
        assert_eq!(err.code, "passphrase_invalid");
        assert_eq!(err.message, "Senha do cofre incorreta.");
    }

    #[test]
    fn pending_list_parses_summary_fields() {
        let raw = br#"{"ok":true,"data":{"requests":[{"requestId":"r1","createdAt":"2026-10-20T10:00:00Z","expiresAt":"2026-10-20T10:05:00Z","summary":{"operationId":"login","entryId":"SENHA","action":"http.request","target":"https://portal","method":"POST","parameters":{"usuario":"ana"},"referencedEntries":["CPF"]}}]}}"#;
        let list: PendingList = decode_response(raw).unwrap();
        let request = &list.requests[0];
        assert_eq!(request.summary.method.as_deref(), Some("POST"));
        assert_eq!(request.summary.parameters["usuario"], "ana");
        assert_eq!(request.summary.referenced_entries, vec!["CPF"]);
    }
}
