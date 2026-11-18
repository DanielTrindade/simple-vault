pub use svault_client::{
    AuthorizeRequest, BrokerError, EntryMetadata as Entry, HealthInfo as Health, HttpSpec,
    OkResult, OperationMetadata as Operation, PendingRequest, ProcessSpec, Result,
};

#[derive(Clone)]
pub struct BrokerClient {
    inner: svault_client::BrokerClient,
}

impl Default for BrokerClient {
    fn default() -> Self {
        Self::from_env()
    }
}

impl BrokerClient {
    pub fn from_env() -> Self {
        Self {
            inner: svault_client::BrokerClient::from_env(),
        }
    }

    pub fn health(&self) -> Result<Health> {
        self.inner.health()
    }

    pub fn list_entries(&self) -> Result<Vec<Entry>> {
        self.inner.list_entries()
    }

    pub fn list_operations(&self) -> Result<Vec<Operation>> {
        self.inner.list_operations()
    }

    pub fn pending_approvals(&self) -> Result<Vec<PendingRequest>> {
        self.inner.pending_approvals()
    }

    pub fn init_vault(&self, passphrase: &str, enable_totp: bool) -> Result<OkResult> {
        self.inner.init_vault(passphrase, enable_totp)
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
        self.inner
            .register_entry(id, kind, label, targets, value, passphrase)
    }

    pub fn update_entry(
        &self,
        id: &str,
        label: Option<&str>,
        targets: &[String],
        value: Option<&str>,
        passphrase: &str,
    ) -> Result<Entry> {
        self.inner
            .update_entry(id, value, label, Some(targets), passphrase)
    }

    pub fn delete_entry(&self, id: &str, passphrase: &str) -> Result<OkResult> {
        self.inner.delete_entry(id, passphrase)
    }

    pub fn authorize_operation(&self, request: &AuthorizeRequest, passphrase: &str) -> Result<Operation> {
        self.inner.authorize_operation(request, passphrase)
    }

    pub fn revoke_operation(&self, id: &str, passphrase: &str) -> Result<OkResult> {
        self.inner.revoke_operation(id, passphrase)
    }

    pub fn approve(&self, request_id: &str, passphrase: &str, totp: Option<&str>) -> Result<OkResult> {
        self.inner.approve(request_id, passphrase, totp)
    }

    pub fn reject(&self, request_id: &str, passphrase: &str) -> Result<OkResult> {
        self.inner.reject(request_id, passphrase)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;
    use std::io::Cursor;
    use svault_client::{
        MAX_RESPONSE_BYTES, PendingList, decode_response, encode_request, read_frame, write_frame,
    };

    #[test]
    fn frame_round_trip_uses_little_endian_length() {
        let mut buffer = Vec::new();
        write_frame(&mut buffer, b"{\"cmd\":\"health\"}").unwrap();
        assert_eq!(&buffer[..4], &16u32.to_le_bytes());
        let payload = read_frame(&mut Cursor::new(buffer), MAX_RESPONSE_BYTES).unwrap();
        assert_eq!(payload, b"{\"cmd\":\"health\"}");
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
        let spec = HttpSpec {
            method: "POST".into(),
            content_type: "application/json".into(),
            ..Default::default()
        };
        let json = serde_json::to_value(Probe {
            entry_id: "SENHA",
            http: &spec,
        })
        .unwrap();
        assert_eq!(json["entryId"], "SENHA");
        assert_eq!(json["contentType"], "application/json");
        assert!(json.get("bodyFields").is_some());
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

    #[test]
    fn envelope_without_body_matches_broker_contract() {
        let bytes = encode_request::<()>("health", None).unwrap();
        assert_eq!(std::str::from_utf8(&bytes).unwrap(), r#"{"cmd":"health"}"#);
    }
}
