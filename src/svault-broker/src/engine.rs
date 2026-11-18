use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, SecondsFormat, Utc};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use svault_core::config::BrokerConfig;
use svault_core::crypto::{Totp, VaultCrypto};
use svault_core::logging::VaultLog;
use svault_core::operations::{OperationContext, OperationEngine, OperationFailure};
use svault_core::protocol::{
    EntryMetadata, Envelope, EnvelopeResponse, HealthInfo, OperationMetadata, OperationOutcome,
    OperationRequestResult, OperationStatusResult, OperationSummary, PendingRequest,
    approval_requirements, error_codes, operation_statuses,
};
use svault_core::redaction::SecretRedactor;
use svault_core::storage::{
    HttpRequestRecord, OperationRecord, ProcessRecord, TargetPolicy, VaultError, VaultStore,
};

use crate::{machine_name, service_identity};

#[derive(Debug, Clone)]
pub struct PendingOperation {
    pub request_id: String,
    pub operation: OperationRecord,
    pub parameters: BTreeMap<String, String>,
    pub created_at: String,
    pub expires_at: String,
    pub authorization_id: String,
    pub entry_revisions: HashMap<String, i32>,
    pub entry_identities: HashMap<String, String>,
    pub status: String,
    pub finished_at: Option<String>,
    pub result: Option<OperationOutcome>,
    pub error: Option<String>,
}

fn now_iso() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true)
}

fn eq_ci(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b) || a.to_lowercase() == b.to_lowercase()
}

fn parse_iso(ts: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(ts)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

enum DispatchError {
    Vault(VaultError),
    Operation(OperationFailure),
}

impl From<VaultError> for DispatchError {
    fn from(err: VaultError) -> Self {
        Self::Vault(err)
    }
}

impl From<OperationFailure> for DispatchError {
    fn from(err: OperationFailure) -> Self {
        Self::Operation(err)
    }
}

pub struct BrokerEngine {
    store: Arc<VaultStore>,
    log: Arc<VaultLog>,
    config: BrokerConfig,
    pending: Mutex<HashMap<String, PendingOperation>>,
}

impl BrokerEngine {
    pub fn new(store: Arc<VaultStore>, log: Arc<VaultLog>, config: BrokerConfig) -> Self {
        Self {
            store,
            log,
            config,
            pending: Mutex::new(HashMap::new()),
        }
    }

    pub async fn handle_async(&self, envelope: Envelope, client_sid: &str) -> EnvelopeResponse {
        let cmd = envelope.cmd.clone();
        match self.dispatch_async(envelope, client_sid).await {
            Ok(resp) => resp,
            Err(DispatchError::Vault(VaultError::Vault { code, message })) => {
                self.log.write(
                    "command_error",
                    [
                        ("cmd", json!(cmd)),
                        ("code", json!(code)),
                        ("client", json!(client_sid)),
                    ],
                );
                EnvelopeResponse::failure(code, message)
            }
            Err(DispatchError::Operation(failure)) => {
                EnvelopeResponse::failure(error_codes::BAD_REQUEST, failure.message)
            }
            Err(DispatchError::Vault(VaultError::Io(_))) => {
                self.log.write(
                    "internal_error",
                    [
                        ("cmd", json!(cmd)),
                        ("type", json!("IoError")),
                        ("client", json!(client_sid)),
                    ],
                );
                EnvelopeResponse::failure(error_codes::INTERNAL, "Falha interna no broker.")
            }
        }
    }

    async fn dispatch_async(
        &self,
        envelope: Envelope,
        client_sid: &str,
    ) -> Result<EnvelopeResponse, DispatchError> {
        let body = envelope.body.unwrap_or_else(|| json!({}));

        match envelope.cmd.as_str() {
            "health" => Ok(EnvelopeResponse::success(self.health())),
            "list_entries" => {
                let entries: Vec<EntryMetadata> = self
                    .store
                    .state()
                    .entries
                    .into_iter()
                    .map(|e| EntryMetadata {
                        id: e.id,
                        kind: e.kind,
                        label: e.label,
                        targets: e.targets,
                        created_at: e.created_at,
                        updated_at: e.updated_at,
                        revision: e.revision,
                    })
                    .collect();
                Ok(EnvelopeResponse::success(json!({ "entries": entries })))
            }
            "list_operations" => {
                let operations: Vec<OperationMetadata> = self
                    .store
                    .state()
                    .operations
                    .into_iter()
                    .map(|o| OperationMetadata {
                        id: o.id,
                        entry_id: o.entry_id,
                        action: o.action,
                        target: o.target,
                        requires_approval: o.requires_approval,
                        description: o.description,
                        params: o.params,
                    })
                    .collect();
                Ok(EnvelopeResponse::success(
                    json!({ "operations": operations }),
                ))
            }
            "request_operation" => Ok(EnvelopeResponse::success(
                self.request_operation(&body, client_sid)?,
            )),
            "operation_status" => Ok(EnvelopeResponse::success(self.operation_status(&body)?)),
            "pending_approvals" => Ok(EnvelopeResponse::success(self.pending_approvals())),
            "init_vault" => Ok(EnvelopeResponse::success(self.init_vault(&body)?)),
            "register_entry" => Ok(EnvelopeResponse::success(self.register_entry(&body)?)),
            "update_entry" => Ok(EnvelopeResponse::success(self.update_entry(&body)?)),
            "delete_entry" => Ok(EnvelopeResponse::success(self.delete_entry(&body)?)),
            "authorize_operation" => {
                Ok(EnvelopeResponse::success(self.authorize_operation(&body)?))
            }
            "revoke_operation" => Ok(EnvelopeResponse::success(self.revoke_operation(&body)?)),
            "approve" => self.approve_async(&body, client_sid).await,
            "reject" => Ok(EnvelopeResponse::success(self.reject(&body)?)),
            "set_totp" => Ok(EnvelopeResponse::success(self.set_totp(&body)?)),
            "disable_totp" => Ok(EnvelopeResponse::success(self.disable_totp(&body)?)),
            "change_passphrase" => Ok(EnvelopeResponse::success(self.change_passphrase(&body)?)),
            "reset_vault" => Ok(EnvelopeResponse::success(self.reset_vault(&body)?)),
            other => Ok(EnvelopeResponse::failure(
                error_codes::BAD_REQUEST,
                format!("Comando desconhecido: {other}"),
            )),
        }
    }

    fn health(&self) -> HealthInfo {
        let state = self.store.state();
        HealthInfo {
            status: "ok".to_owned(),
            version: self.config.version.clone(),
            service_identity: service_identity(),
            vault_initialized: state.initialized,
            totp_required: self.store.totp_enabled(),
            state_path: self.store.state_path().to_string_lossy().into_owned(),
            entry_count: state.entries.len() as i32,
            operation_count: state.operations.len() as i32,
        }
    }

    fn pending_approvals(&self) -> Value {
        let mut map = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        Self::expire_pending_locked(&mut map);
        let mut requests: Vec<PendingRequest> = map
            .values()
            .filter(|r| r.status == operation_statuses::PENDING_APPROVAL)
            .map(|r| PendingRequest {
                request_id: r.request_id.clone(),
                created_at: r.created_at.clone(),
                expires_at: r.expires_at.clone(),
                summary: Self::summarize(&r.operation, Some(&r.parameters)),
            })
            .collect();
        requests.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        json!({ "requests": requests })
    }

    fn request_operation(
        &self,
        body: &Value,
        client_sid: &str,
    ) -> Result<OperationRequestResult, DispatchError> {
        let mut map = self.pending.lock().unwrap_or_else(|e| e.into_inner());

        let op_id = read_string(body, "opId")?;
        let parameters = read_parameters(body)?;
        let state = self.store.state();

        let operation = state
            .operations
            .iter()
            .find(|o| eq_ci(&o.id, &op_id))
            .cloned()
            .ok_or_else(|| {
                VaultError::new(
                    error_codes::NOT_FOUND,
                    format!("Operacao nao encontrada: {op_id}"),
                )
            })?;

        OperationEngine::validate_parameters(&operation, &parameters)?;

        let entry = state
            .entries
            .iter()
            .find(|e| eq_ci(&e.id, &operation.entry_id))
            .ok_or_else(|| {
                VaultError::new(
                    error_codes::NOT_FOUND,
                    format!("Registro nao encontrado: {}", operation.entry_id),
                )
            })?;

        if operation.action != OperationEngine::ACTION_NOOP_ECHO
            && !TargetPolicy::is_target_allowed(&entry.targets, &operation.target)
        {
            return Err(VaultError::new(
                error_codes::TARGET_NOT_ALLOWED,
                format!(
                    "O alvo {} nao esta autorizado para o registro {}.",
                    operation.target, entry.id
                ),
            )
            .into());
        }

        Self::expire_pending_locked(&mut map);
        let pending_count = map
            .values()
            .filter(|r| r.status == operation_statuses::PENDING_APPROVAL)
            .count();
        if pending_count >= 500 {
            return Err(VaultError::new(
                error_codes::CONFLICT,
                "A fila de aprovacoes atingiu o limite.",
            )
            .into());
        }

        let mut revisions = HashMap::new();
        let mut identities = HashMap::new();
        revisions.insert(entry.id.clone(), entry.revision);
        identities.insert(entry.id.clone(), entry.identity_id.clone());

        for ref_id in OperationEngine::collect_referenced_entries(&operation) {
            let referenced = state
                .entries
                .iter()
                .find(|e| eq_ci(&e.id, &ref_id))
                .ok_or_else(|| {
                    VaultError::new(
                        error_codes::NOT_FOUND,
                        format!("Segredo referenciado nao encontrado: {ref_id}"),
                    )
                })?;
            revisions.insert(referenced.id.clone(), referenced.revision);
            identities.insert(referenced.id.clone(), referenced.identity_id.clone());
        }

        let request_id = VaultCrypto::random_id();
        let now = Utc::now();
        let created_at = now.to_rfc3339_opts(SecondsFormat::Micros, true);
        let expires_at = (now + Duration::seconds(self.config.approval_ttl_seconds))
            .to_rfc3339_opts(SecondsFormat::Micros, true);

        let summary = Self::summarize(&operation, Some(&parameters));
        let pending = PendingOperation {
            request_id: request_id.clone(),
            authorization_id: operation.authorization_id.clone(),
            operation: operation.clone(),
            parameters,
            entry_revisions: revisions,
            entry_identities: identities,
            created_at,
            expires_at: expires_at.clone(),
            status: operation_statuses::PENDING_APPROVAL.to_owned(),
            finished_at: None,
            result: None,
            error: None,
        };

        map.insert(request_id.clone(), pending);
        drop(map);

        self.log.write(
            "operation_requested",
            [
                ("requestId", json!(request_id)),
                ("operationId", json!(operation.id)),
                ("entryId", json!(operation.entry_id)),
                ("action", json!(operation.action)),
                ("target", json!(operation.target)),
                ("client", json!(client_sid)),
            ],
        );

        let requires = if self.store.totp_enabled() {
            approval_requirements::PASSPHRASE_AND_TOTP
        } else {
            approval_requirements::PASSPHRASE
        };

        Ok(OperationRequestResult {
            request_id,
            status: operation_statuses::PENDING_APPROVAL.to_owned(),
            requires: requires.to_owned(),
            expires_at,
            summary,
        })
    }

    fn operation_status(&self, body: &Value) -> Result<OperationStatusResult, DispatchError> {
        let request_id = read_string(body, "requestId")?;
        let mut map = self.pending.lock().unwrap_or_else(|e| e.into_inner());

        let pending = map
            .values_mut()
            .find(|r| eq_ci(&r.request_id, &request_id))
            .ok_or_else(|| {
                VaultError::new(error_codes::NOT_FOUND, "Requisicao nao encontrada.")
            })?;

        if pending.status == operation_statuses::PENDING_APPROVAL
            && parse_iso(&pending.expires_at).is_some_and(|exp| Utc::now() > exp)
        {
            pending.status = operation_statuses::EXPIRED.to_owned();
            pending.finished_at = Some(now_iso());
        }

        Ok(Self::build_status_result(pending))
    }

    async fn approve_async(
        &self,
        body: &Value,
        client_sid: &str,
    ) -> Result<EnvelopeResponse, DispatchError> {
        let request_id = read_string(body, "requestId")?;
        let passphrase = Zeroizing::new(read_string(body, "passphrase")?);
        let totp = read_optional_string(body, "totp");

        let (req_key, op_snapshot, params_snapshot, secret, referenced) = {
            let mut map = self.pending.lock().unwrap_or_else(|e| e.into_inner());
            let key = map
                .keys()
                .find(|k| eq_ci(k, &request_id))
                .cloned()
                .ok_or_else(|| {
                    VaultError::new(error_codes::NOT_FOUND, "Requisicao nao encontrada.")
                })?;

            {
                let pending = map.get_mut(&key).unwrap();
                if pending.status != operation_statuses::PENDING_APPROVAL {
                    return Err(VaultError::new(
                        error_codes::CONFLICT,
                        "A requisicao nao esta aguardando aprovacao.",
                    )
                    .into());
                }

                if parse_iso(&pending.expires_at).is_some_and(|exp| Utc::now() > exp) {
                    pending.status = operation_statuses::EXPIRED.to_owned();
                    pending.finished_at = Some(now_iso());
                    return Err(
                        VaultError::new(error_codes::EXPIRED, "A requisicao expirou.").into(),
                    );
                }
            }

            let snapshot_for_validation = map.get(&key).unwrap().clone();
            self.revalidate_authorization(&snapshot_for_validation)?;

            if !self.store.verify_passphrase(&passphrase)? {
                return Err(VaultError::new(
                    error_codes::PASSPHRASE_INVALID,
                    "Senha do cofre invalida.",
                )
                .into());
            }

            if self.store.totp_enabled() {
                let totp_secret = self.store.get_totp_secret(&passphrase)?.ok_or_else(|| {
                    VaultError::new(error_codes::TOTP_REQUIRED, "Codigo TOTP obrigatorio.")
                })?;

                let Some(code) = totp.as_deref().filter(|c| !c.trim().is_empty()) else {
                    return Err(VaultError::new(
                        error_codes::TOTP_REQUIRED,
                        "Codigo TOTP obrigatorio.",
                    )
                    .into());
                };

                if !Totp::verify_code(&totp_secret, code, Utc::now()) {
                    return Err(VaultError::new(
                        error_codes::TOTP_INVALID,
                        "Codigo TOTP invalido.",
                    )
                    .into());
                }
            }

            let (secret, referenced) =
                self.unwrap_approved_secrets(&snapshot_for_validation, &passphrase)?;

            let pending = map.get_mut(&key).unwrap();
            pending.status = operation_statuses::RUNNING.to_owned();
            (
                key,
                pending.operation.clone(),
                pending.parameters.clone(),
                secret,
                referenced,
            )
        };

        let mut all_secret_slices: Vec<&[u8]> = Vec::with_capacity(1 + referenced.len());
        all_secret_slices.push(secret.as_slice());
        for val in referenced.values() {
            all_secret_slices.push(val.as_slice());
        }
        let redactor = SecretRedactor::new(all_secret_slices);

        let context = OperationContext {
            operation: op_snapshot.clone(),
            secret,
            referenced_secrets: referenced,
            parameters: params_snapshot,
            redactor: redactor.clone(),
        };

        match OperationEngine::execute_async(&context).await {
            Ok(mut outcome) => {
                outcome.body = redactor.redact_nullable(outcome.body.as_deref());
                outcome.output = redactor.redact_nullable(outcome.output.as_deref());

                let status_result = {
                    let mut map = self.pending.lock().unwrap_or_else(|e| e.into_inner());
                    let pending = map.get_mut(&req_key).expect("pending exists");
                    pending.result = Some(outcome.clone());
                    pending.status = operation_statuses::COMPLETED.to_owned();
                    pending.finished_at = Some(now_iso());
                    Self::build_status_result(pending)
                };

                self.log.write(
                    "operation_completed",
                    [
                        ("requestId", json!(status_result.request_id)),
                        ("operationId", json!(op_snapshot.id)),
                        ("entryId", json!(op_snapshot.entry_id)),
                        ("ok", json!(outcome.ok)),
                        ("durationMs", json!(outcome.duration_ms)),
                        ("client", json!(client_sid)),
                    ],
                );

                Ok(EnvelopeResponse::success(status_result))
            }
            Err(_) => {
                let status_result = {
                    let mut map = self.pending.lock().unwrap_or_else(|e| e.into_inner());
                    let pending = map.get_mut(&req_key).expect("pending exists");
                    if pending.status != operation_statuses::RUNNING {
                        return Ok(EnvelopeResponse::success(Self::build_status_result(
                            pending,
                        )));
                    }
                    pending.status = operation_statuses::FAILED.to_owned();
                    pending.finished_at = Some(now_iso());
                    pending.error = Some("Falha na execucao autorizada.".to_owned());
                    Self::build_status_result(pending)
                };

                self.log.write(
                    "operation_failed",
                    [
                        ("requestId", json!(status_result.request_id)),
                        ("operationId", json!(op_snapshot.id)),
                        ("type", json!("OperationFailure")),
                        ("client", json!(client_sid)),
                    ],
                );

                Ok(EnvelopeResponse::success(status_result))
            }
        }
    }

    fn reject(&self, body: &Value) -> Result<Value, DispatchError> {
        let request_id = read_string(body, "requestId")?;
        let passphrase = Zeroizing::new(read_string(body, "passphrase")?);

        let mut map = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        if !self.store.verify_passphrase(&passphrase)? {
            return Err(VaultError::new(
                error_codes::PASSPHRASE_INVALID,
                "Senha do cofre invalida.",
            )
            .into());
        }

        let pending = map
            .values_mut()
            .find(|r| eq_ci(&r.request_id, &request_id))
            .ok_or_else(|| {
                VaultError::new(error_codes::NOT_FOUND, "Requisicao nao encontrada.")
            })?;

        if pending.status != operation_statuses::PENDING_APPROVAL {
            return Err(VaultError::new(
                error_codes::CONFLICT,
                "Somente solicitacoes pendentes podem ser rejeitadas.",
            )
            .into());
        }

        pending.status = operation_statuses::REJECTED.to_owned();
        pending.finished_at = Some(now_iso());

        Ok(json!({
            "requestId": pending.request_id,
            "status": pending.status,
        }))
    }

    fn init_vault(&self, body: &Value) -> Result<Value, DispatchError> {
        let passphrase = Zeroizing::new(read_string(body, "passphrase")?);
        let enable_totp = read_optional_bool(body, "enableTotp").unwrap_or(false);
        let totp_secret = read_optional_string(body, "totpSecret").map(Zeroizing::new);

        let generated = Zeroizing::new(self.store.initialize(
            &passphrase,
            enable_totp,
            totp_secret.as_deref().map(String::as_str),
        )?);

        self.log
            .write("vault_initialized", [("totp", json!(enable_totp))]);

        let totp_uri = if enable_totp {
            let effective = totp_secret
                .as_deref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .unwrap_or(generated.as_str());
            Some(Totp::build_otp_auth_uri(
                effective,
                &machine_name(),
                "SVault",
            ))
        } else {
            None
        };

        Ok(json!({
            "initialized": true,
            "totpEnabled": enable_totp,
            "totpUri": totp_uri,
        }))
    }

    fn register_entry(&self, body: &Value) -> Result<Value, DispatchError> {
        let id = read_string(body, "id")?;
        let kind = read_optional_string(body, "kind").unwrap_or_else(|| "generic".to_owned());
        let label = read_optional_string(body, "label").unwrap_or_else(|| id.clone());
        let targets = read_string_array(body, "targets");
        let passphrase = Zeroizing::new(read_string(body, "passphrase")?);
        let value = read_secret(body, "value")?;

        let record =
            self.store
                .register_entry(&id, &kind, &label, &targets, &value, &passphrase)?;

        self.log.write(
            "entry_registered",
            [("id", json!(record.id)), ("kind", json!(record.kind))],
        );

        Ok(json!({
            "id": record.id,
            "kind": record.kind,
            "label": record.label,
            "targets": record.targets,
            "createdAt": record.created_at,
            "updatedAt": record.updated_at,
            "revision": record.revision,
        }))
    }

    fn update_entry(&self, body: &Value) -> Result<Value, DispatchError> {
        let id = read_string(body, "id")?;
        let passphrase = Zeroizing::new(read_string(body, "passphrase")?);
        let label = read_optional_string(body, "label");
        let targets = read_optional_string_array(body, "targets");
        let value = read_optional_secret(body, "value");

        let record = self.store.update_entry(
            &id,
            value.as_deref().map(Vec::as_slice),
            label.as_deref(),
            targets.as_deref(),
            &passphrase,
        )?;

        self.log.write(
            "entry_updated",
            [
                ("id", json!(record.id)),
                ("revision", json!(record.revision)),
            ],
        );

        Ok(json!({
            "id": record.id,
            "kind": record.kind,
            "label": record.label,
            "targets": record.targets,
            "createdAt": record.created_at,
            "updatedAt": record.updated_at,
            "revision": record.revision,
        }))
    }

    fn delete_entry(&self, body: &Value) -> Result<Value, DispatchError> {
        let id = read_string(body, "id")?;
        let passphrase = Zeroizing::new(read_string(body, "passphrase")?);

        self.store.delete_entry(&id, &passphrase)?;
        self.log.write("entry_deleted", [("id", json!(id))]);

        Ok(json!({ "id": id, "deleted": true }))
    }

    fn authorize_operation(&self, body: &Value) -> Result<Value, DispatchError> {
        let id = read_string(body, "id")?;
        let entry_id = read_string(body, "entryId")?;
        let action = read_string(body, "action")?;
        let target = read_string(body, "target")?;
        let description = read_optional_string(body, "description").unwrap_or_default();
        let param_names = read_string_array(body, "params");
        let passphrase = Zeroizing::new(read_string(body, "passphrase")?);

        if action == OperationEngine::ACTION_PROCESS_STDIN {
            return Err(VaultError::new(
                error_codes::BAD_REQUEST,
                "Acoes de processo estao desabilitadas pelo contrato de seguranca atual.",
            )
            .into());
        }

        if !OperationEngine::SUPPORTED_ACTIONS.contains(&action.as_str()) {
            return Err(VaultError::new(
                error_codes::BAD_REQUEST,
                format!("Acao nao suportada: {action}"),
            )
            .into());
        }

        let mut record = OperationRecord {
            authorization_id: VaultCrypto::random_id(),
            id,
            entry_id,
            action: action.clone(),
            target: target.clone(),
            requires_approval: true,
            description,
            params: param_names,
            http: None,
            process: None,
        };

        if action == OperationEngine::ACTION_HTTP_REQUEST {
            let http = HttpRequestRecord {
                method: read_optional_string(body, "method").unwrap_or_else(|| "POST".to_owned()),
                url: read_optional_string(body, "url").unwrap_or_else(|| target.clone()),
                content_type: read_optional_string(body, "contentType")
                    .unwrap_or_else(|| "application/json".to_owned()),
                body_fields: read_string_map(body, "bodyFields"),
                headers: read_string_map(body, "headers"),
                result_fields: read_string_array(body, "resultFields"),
            };

            if !TargetPolicy::are_equivalent_urls(&http.url, &target) {
                return Err(VaultError::new(
                    error_codes::BAD_REQUEST,
                    "A URL deve ser igual ao alvo autorizado.",
                )
                .into());
            }

            record.http = Some(http);
            OperationEngine::validate_templates(&record)?;

            if let Some(http_ref) = &record.http {
                self.validate_no_secret_literal(
                    http_ref.body_fields.values().map(String::as_str),
                    &passphrase,
                )?;
                self.validate_no_secret_literal(
                    http_ref.headers.values().map(String::as_str),
                    &passphrase,
                )?;
            }
        } else if action == OperationEngine::ACTION_PROCESS_STDIN {
            let proc_rec = ProcessRecord {
                executable: read_optional_string(body, "executable")
                    .unwrap_or_else(|| target.clone()),
                args: read_string_array(body, "args"),
                env: read_string_array(body, "env"),
                timeout_seconds: read_optional_int(body, "timeoutSeconds").unwrap_or(30),
            };
            if !eq_ci(&proc_rec.executable, &target) {
                return Err(VaultError::new(
                    error_codes::BAD_REQUEST,
                    "O executavel deve ser igual ao alvo autorizado.",
                )
                .into());
            }
            self.validate_no_secret_literal(proc_rec.args.iter().map(String::as_str), &passphrase)?;
            self.validate_no_secret_literal(proc_rec.env.iter().map(String::as_str), &passphrase)?;
            record.process = Some(proc_rec);
        }

        let state = self.store.state();
        for ref_id in OperationEngine::collect_referenced_entries(&record) {
            let ref_entry = state
                .entries
                .iter()
                .find(|e| eq_ci(&e.id, &ref_id))
                .ok_or_else(|| {
                    VaultError::new(
                        error_codes::NOT_FOUND,
                        format!("Segredo referenciado nao encontrado: {ref_id}"),
                    )
                })?;

            if !TargetPolicy::is_target_allowed(&ref_entry.targets, &record.target) {
                return Err(VaultError::new(
                    error_codes::TARGET_NOT_ALLOWED,
                    format!(
                        "O alvo {} nao esta autorizado para o registro {}.",
                        record.target, ref_entry.id
                    ),
                )
                .into());
            }
        }

        let stored = self.store.authorize_operation(record, &passphrase)?;

        self.log.write(
            "operation_authorized",
            [
                ("id", json!(stored.id)),
                ("entryId", json!(stored.entry_id)),
                ("action", json!(stored.action)),
                ("target", json!(stored.target)),
            ],
        );

        Ok(json!({
            "id": stored.id,
            "entryId": stored.entry_id,
            "action": stored.action,
            "target": stored.target,
            "requiresApproval": stored.requires_approval,
            "description": stored.description,
            "params": stored.params,
            "paramNames": stored.params,
        }))
    }

    fn revoke_operation(&self, body: &Value) -> Result<Value, DispatchError> {
        let id = read_string(body, "id")?;
        let passphrase = Zeroizing::new(read_string(body, "passphrase")?);

        let mut map = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        self.store.revoke_operation(&id, &passphrase)?;
        for pending in map.values_mut() {
            if pending.status == operation_statuses::PENDING_APPROVAL
                && eq_ci(&pending.operation.id, &id)
            {
                pending.status = operation_statuses::REVOKED.to_owned();
                pending.finished_at = Some(now_iso());
            }
        }
        drop(map);

        self.log.write("operation_revoked", [("id", json!(id))]);
        Ok(json!({ "id": id, "revoked": true }))
    }

    fn set_totp(&self, body: &Value) -> Result<Value, DispatchError> {
        let secret = Zeroizing::new(read_string(body, "secret")?);
        let passphrase = Zeroizing::new(read_string(body, "passphrase")?);
        let totp = read_optional_string(body, "totp");

        self.store
            .set_totp(&secret, &passphrase, totp.as_deref())?;
        self.log
            .write("totp_enabled", std::iter::empty::<(&str, Value)>());
        Ok(json!({ "totpEnabled": true }))
    }

    fn disable_totp(&self, body: &Value) -> Result<Value, DispatchError> {
        let passphrase = Zeroizing::new(read_string(body, "passphrase")?);
        let totp = read_optional_string(body, "totp");

        self.store.disable_totp(&passphrase, totp.as_deref())?;
        self.log
            .write("totp_disabled", std::iter::empty::<(&str, Value)>());
        Ok(json!({ "totpEnabled": false }))
    }

    fn change_passphrase(&self, body: &Value) -> Result<Value, DispatchError> {
        let current = Zeroizing::new(read_string(body, "currentPassphrase")?);
        let next = Zeroizing::new(read_string(body, "newPassphrase")?);
        let totp = read_optional_string(body, "totp");

        self.store
            .change_passphrase(&current, &next, totp.as_deref())?;
        self.log
            .write("passphrase_changed", std::iter::empty::<(&str, Value)>());
        Ok(json!({ "changed": true }))
    }

    fn reset_vault(&self, body: &Value) -> Result<Value, DispatchError> {
        let passphrase = Zeroizing::new(read_string(body, "passphrase")?);
        let totp = read_optional_string(body, "totp");

        let removed = self.store.reset(&passphrase, totp.as_deref())?;
        self.log
            .write("vault_reset", [("entriesRemoved", json!(removed))]);
        Ok(json!({
            "reset": true,
            "entriesRemoved": removed,
            "initialized": false,
        }))
    }

    fn validate_no_secret_literal<'a, I>(
        &self,
        templates: I,
        passphrase: &str,
    ) -> Result<(), VaultError>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let literals = OperationEngine::literal_segments(templates);
        if literals.is_empty() {
            return Ok(());
        }

        let secrets = self.store.unwrap_all_secrets(passphrase)?;
        for (entry_id, secret) in &secrets {
            let text = Zeroizing::new(String::from_utf8_lossy(secret).into_owned());
            if !text.is_empty() && literals.iter().any(|l| l.contains(text.as_str())) {
                return Err(VaultError::new(
                    error_codes::BAD_REQUEST,
                    format!(
                        "O template contem literalmente o segredo do registro {entry_id}. Use apenas os placeholders."
                    ),
                ));
            }
        }
        Ok(())
    }

    fn revalidate_authorization(&self, pending: &PendingOperation) -> Result<(), VaultError> {
        let state = self.store.state();
        let current_op = state
            .operations
            .iter()
            .find(|o| eq_ci(&o.id, &pending.operation.id));

        let Some(current_op) = current_op else {
            return Err(VaultError::new(
                error_codes::CONFLICT,
                "A operacao foi revogada ou substituida.",
            ));
        };

        if current_op.authorization_id != pending.authorization_id {
            return Err(VaultError::new(
                error_codes::CONFLICT,
                "A operacao foi revogada ou substituida.",
            ));
        }

        if pending.operation.action == OperationEngine::ACTION_HTTP_REQUEST {
            let valid_url = pending
                .operation
                .http
                .as_ref()
                .is_some_and(|h| TargetPolicy::are_equivalent_urls(&h.url, &pending.operation.target));
            if !valid_url {
                return Err(VaultError::new(
                    error_codes::TARGET_NOT_ALLOWED,
                    "A URL efetiva da operacao difere do alvo autorizado; autorize novamente.",
                ));
            }
        }

        for (entry_id, &revision) in &pending.entry_revisions {
            let current = state.entries.iter().find(|e| eq_ci(&e.id, entry_id));
            let expected_identity = pending
                .entry_identities
                .iter()
                .find(|(k, _)| eq_ci(k, entry_id))
                .map(|(_, v)| v.as_str());

            let Some(current) = current else {
                return Err(VaultError::new(
                    error_codes::CONFLICT,
                    "Um registro usado pela solicitacao foi alterado.",
                ));
            };

            if current.revision != revision
                || expected_identity != Some(current.identity_id.as_str())
            {
                return Err(VaultError::new(
                    error_codes::CONFLICT,
                    "Um registro usado pela solicitacao foi alterado.",
                ));
            }

            if pending.operation.action != OperationEngine::ACTION_NOOP_ECHO
                && !TargetPolicy::is_target_allowed(&current.targets, &pending.operation.target)
            {
                return Err(VaultError::new(
                    error_codes::TARGET_NOT_ALLOWED,
                    "O alvo deixou de estar autorizado.",
                ));
            }
        }

        Ok(())
    }

    fn unwrap_approved_secrets(
        &self,
        pending: &PendingOperation,
        passphrase: &str,
    ) -> Result<
        (
            Zeroizing<Vec<u8>>,
            HashMap<String, Zeroizing<Vec<u8>>>,
        ),
        VaultError,
    > {
        let secret = self
            .store
            .unwrap_secret(&pending.operation.entry_id, passphrase)?;
        let state = self.store.state();
        let referenced_ids = OperationEngine::collect_referenced_entries(&pending.operation);

        for ref_id in &referenced_ids {
            let entry = state
                .entries
                .iter()
                .find(|e| eq_ci(&e.id, ref_id))
                .ok_or_else(|| {
                    VaultError::new(
                        error_codes::CONFLICT,
                        "Um registro usado pela solicitacao nao existe mais.",
                    )
                })?;

            if pending.operation.action != OperationEngine::ACTION_NOOP_ECHO
                && !TargetPolicy::is_target_allowed(&entry.targets, &pending.operation.target)
            {
                return Err(VaultError::new(
                    error_codes::TARGET_NOT_ALLOWED,
                    "O alvo deixou de estar autorizado.",
                ));
            }
        }

        let referenced = self
            .store
            .unwrap_secrets(referenced_ids.iter().map(String::as_str), passphrase)?;

        for ref_id in &referenced_ids {
            if !referenced.keys().any(|k| eq_ci(k, ref_id)) {
                return Err(VaultError::new(
                    error_codes::NOT_FOUND,
                    "Um segredo referenciado nao esta disponivel.",
                ));
            }
        }

        Ok((secret, referenced))
    }

    fn expire_pending_locked(map: &mut HashMap<String, PendingOperation>) {
        let now = Utc::now();
        for pending in map.values_mut() {
            if pending.status == operation_statuses::PENDING_APPROVAL
                && parse_iso(&pending.expires_at).is_some_and(|exp| now > exp)
            {
                pending.status = operation_statuses::EXPIRED.to_owned();
                pending.finished_at = Some(now_iso());
            }
        }

        if map.len() > 1000 {
            let excess = map.len() - 1000;
            let mut candidates: Vec<(String, String)> = map
                .values()
                .filter(|p| {
                    p.status != operation_statuses::PENDING_APPROVAL
                        && p.status != operation_statuses::RUNNING
                })
                .map(|p| {
                    (
                        p.request_id.clone(),
                        p.finished_at.clone().unwrap_or_default(),
                    )
                })
                .collect();
            candidates.sort_by(|a, b| a.1.cmp(&b.1));
            for (req_id, _) in candidates.into_iter().take(excess) {
                map.remove(&req_id);
            }
        }
    }

    fn summarize(
        operation: &OperationRecord,
        parameters: Option<&BTreeMap<String, String>>,
    ) -> OperationSummary {
        OperationSummary {
            operation_id: operation.id.clone(),
            entry_id: operation.entry_id.clone(),
            action: operation.action.clone(),
            target: operation.target.clone(),
            requires_approval: operation.requires_approval,
            description: operation.description.clone(),
            parameters: parameters.cloned().unwrap_or_default(),
            method: operation.http.as_ref().map(|h| h.method.clone()),
            referenced_entries: OperationEngine::collect_referenced_entries(operation),
        }
    }

    fn build_status_result(pending: &PendingOperation) -> OperationStatusResult {
        OperationStatusResult {
            request_id: pending.request_id.clone(),
            status: pending.status.clone(),
            summary: Self::summarize(&pending.operation, Some(&pending.parameters)),
            created_at: pending.created_at.clone(),
            finished_at: pending.finished_at.clone(),
            result: pending.result.clone(),
            error: pending.error.clone(),
        }
    }
}

fn read_string(body: &Value, name: &str) -> Result<String, VaultError> {
    let Some(val) = body.get(name).and_then(Value::as_str) else {
        return Err(VaultError::new(
            error_codes::BAD_REQUEST,
            format!("Campo obrigatorio ausente: {name}"),
        ));
    };
    if val.trim().is_empty() {
        return Err(VaultError::new(
            error_codes::BAD_REQUEST,
            format!("Campo obrigatorio vazio: {name}"),
        ));
    }
    Ok(val.to_owned())
}

fn read_optional_string(body: &Value, name: &str) -> Option<String> {
    body.get(name)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

fn read_optional_bool(body: &Value, name: &str) -> Option<bool> {
    body.get(name).and_then(Value::as_bool)
}

fn read_optional_int(body: &Value, name: &str) -> Option<i32> {
    body.get(name)
        .and_then(Value::as_i64)
        .and_then(|v| i32::try_from(v).ok())
}

fn read_secret(body: &Value, name: &str) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let Some(val) = read_optional_string(body, name).map(Zeroizing::new) else {
        return Err(VaultError::new(
            error_codes::BAD_REQUEST,
            format!("Campo obrigatorio ausente: {name}"),
        ));
    };
    Ok(Zeroizing::new(val.as_bytes().to_vec()))
}

fn read_optional_secret(body: &Value, name: &str) -> Option<Zeroizing<Vec<u8>>> {
    read_optional_string(body, name)
        .map(Zeroizing::new)
        .map(|s| Zeroizing::new(s.as_bytes().to_vec()))
}

fn read_string_array(body: &Value, name: &str) -> Vec<String> {
    body.get(name)
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn read_optional_string_array(body: &Value, name: &str) -> Option<Vec<String>> {
    body.get(name).and_then(Value::as_array).map(|arr| {
        arr.iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect()
    })
}

fn read_string_map(body: &Value, name: &str) -> BTreeMap<String, String> {
    body.get(name)
        .and_then(Value::as_object)
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
                .collect()
        })
        .unwrap_or_default()
}

fn read_parameters(body: &Value) -> Result<BTreeMap<String, String>, VaultError> {
    let Some(element) = body.get("params") else {
        return Ok(BTreeMap::new());
    };
    if element.is_null() {
        return Ok(BTreeMap::new());
    }
    let Some(obj) = element.as_object() else {
        return Err(VaultError::new(
            error_codes::BAD_REQUEST,
            "O campo params deve ser um objeto de strings.",
        ));
    };

    let mut params = BTreeMap::new();
    for (k, v) in obj {
        let Some(text) = v.as_str() else {
            return Err(VaultError::new(
                error_codes::BAD_REQUEST,
                format!("O parametro {k} deve ser texto."),
            ));
        };
        params.insert(k.clone(), text.to_owned());
    }
    Ok(params)
}
