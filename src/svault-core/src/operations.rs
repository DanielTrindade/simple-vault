use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::LazyLock;
#[cfg(feature = "http")]
use std::time::Instant;

use regex::{Captures, Regex};
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use crate::protocol::OperationOutcome;
use crate::redaction::SecretRedactor;
use crate::storage::store::eq_ci;
#[cfg(feature = "http")]
use crate::storage::TargetPolicy;
use crate::storage::{HttpRequestRecord, OperationRecord};

static TOKEN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\{\{(secret(?::[^{}]+)?|param:[^{}]+)\}\}").unwrap());
static PARAM_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\{\{param:([^{}]+)\}\}").unwrap());
static SPLIT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\{\{(?:secret(?::[^{}]+)?|param:[^{}]+)\}\}").unwrap());

#[derive(Debug, Clone)]
pub struct OperationFailure {
    pub message: String,
}

impl OperationFailure {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for OperationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for OperationFailure {}

pub struct OperationContext {
    pub operation: OperationRecord,
    pub secret: Zeroizing<Vec<u8>>,
    pub referenced_secrets: HashMap<String, Zeroizing<Vec<u8>>>,
    pub parameters: BTreeMap<String, String>,
    pub redactor: SecretRedactor,
}

impl OperationContext {
    pub fn secret_text(&self) -> String {
        String::from_utf8_lossy(&self.secret).into_owned()
    }

    pub fn get_referenced_secret(&self, id: &str) -> Option<String> {
        self.referenced_secrets
            .iter()
            .find(|(k, _)| eq_ci(k, id))
            .map(|(_, v)| String::from_utf8_lossy(v).into_owned())
    }

    pub fn get_parameter(&self, name: &str) -> Option<&str> {
        self.parameters
            .iter()
            .find(|(k, _)| eq_ci(k, name))
            .map(|(_, v)| v.as_str())
    }
}

pub struct OperationEngine;

impl OperationEngine {
    pub const ACTION_NOOP_ECHO: &'static str = "noop.echo";
    pub const ACTION_HTTP_REQUEST: &'static str = "http.request";
    pub const ACTION_PROCESS_STDIN: &'static str = "process.stdin";

    pub const PLACEHOLDER_SECRET: &'static str = "{{secret}}";
    pub const PARAM_PREFIX: &'static str = "{{param:";
    pub const SECRET_PREFIX: &'static str = "{{secret:";

    pub const SUPPORTED_ACTIONS: [&'static str; 2] =
        [Self::ACTION_NOOP_ECHO, Self::ACTION_HTTP_REQUEST];

    pub fn collect_referenced_entries(operation: &OperationRecord) -> Vec<String> {
        let mut templates: Vec<&str> = Vec::new();
        if let Some(http) = &operation.http {
            templates.extend(http.body_fields.values().map(String::as_str));
            templates.extend(http.headers.values().map(String::as_str));
        }
        if let Some(proc_spec) = &operation.process {
            templates.extend(proc_spec.args.iter().map(String::as_str));
            templates.extend(proc_spec.env.iter().map(String::as_str));
        }

        let mut ids: Vec<String> = Vec::new();
        for template in templates {
            let mut search_from = 0usize;
            while let Some(rel_idx) = template[search_from..].find(Self::SECRET_PREFIX) {
                let idx = search_from + rel_idx;
                let after_prefix = idx + Self::SECRET_PREFIX.len();
                let Some(rel_end) = template[after_prefix..].find("}}") else {
                    break;
                };
                let end = after_prefix + rel_end;
                let id = template[after_prefix..end].trim();
                if !id.is_empty() && !ids.iter().any(|existing| eq_ci(existing, id)) {
                    ids.push(id.to_owned());
                }
                search_from = end + 2;
            }
        }

        ids
    }

    pub fn literal_segments<'a, I>(templates: I) -> Vec<String>
    where
        I: IntoIterator<Item = &'a str>,
    {
        templates
            .into_iter()
            .filter(|t| !t.is_empty())
            .flat_map(|t| SPLIT_RE.split(t))
            .filter(|seg| !seg.is_empty())
            .map(str::to_owned)
            .collect()
    }

    pub fn validate_templates(operation: &OperationRecord) -> Result<(), OperationFailure> {
        let Some(http) = &operation.http else {
            return Ok(());
        };

        for template in http.body_fields.values().chain(http.headers.values()) {
            Self::validate_template(template, &operation.params)?;
        }
        Ok(())
    }

    fn validate_template(
        template: &str,
        declared_parameters: &[String],
    ) -> Result<(), OperationFailure> {
        let remainder = TOKEN_RE.replace_all(template, "");
        if remainder.contains("{{") || remainder.contains("}}") {
            return Err(OperationFailure::new(
                "Template contem placeholder invalido.",
            ));
        }

        for caps in PARAM_RE.captures_iter(template) {
            let name = caps.get(1).map_or("", |m| m.as_str()).trim();
            if name.is_empty() || !declared_parameters.iter().any(|d| eq_ci(d, name)) {
                return Err(OperationFailure::new(
                    "Template usa parametro nao declarado.",
                ));
            }
        }

        Ok(())
    }

    pub fn validate_parameters(
        operation: &OperationRecord,
        parameters: &BTreeMap<String, String>,
    ) -> Result<(), OperationFailure> {
        Self::validate_templates(operation)?;

        for (name, value) in parameters {
            if !operation.params.iter().any(|p| eq_ci(p, name)) {
                return Err(OperationFailure::new(format!(
                    "Parametro nao declarado: {name}"
                )));
            }
            if value.chars().count() > 512 {
                return Err(OperationFailure::new(format!(
                    "Parametro muito longo: {name}"
                )));
            }
            if value.chars().any(char::is_control) {
                return Err(OperationFailure::new(format!(
                    "Parametro invalido: {name}"
                )));
            }
        }

        if let Some(http) = &operation.http {
            let mut required: Vec<String> = Vec::new();
            for template in http.body_fields.values().chain(http.headers.values()) {
                for caps in PARAM_RE.captures_iter(template) {
                    let name = caps.get(1).map_or("", |m| m.as_str()).trim();
                    if !name.is_empty() && !required.iter().any(|r| eq_ci(r, name)) {
                        required.push(name.to_owned());
                    }
                }
            }

            for name in required {
                let present = parameters
                    .iter()
                    .find(|(k, _)| eq_ci(k, &name))
                    .is_some_and(|(_, v)| !v.trim().is_empty());
                if !present {
                    return Err(OperationFailure::new(format!(
                        "Parametro obrigatorio ausente: {name}"
                    )));
                }
            }
        }

        Ok(())
    }

    pub fn resolve_template(
        template: &str,
        context: &OperationContext,
    ) -> Result<String, OperationFailure> {
        Self::validate_template(template, &context.operation.params)?;

        let mut err: Option<OperationFailure> = None;
        let replaced = TOKEN_RE.replace_all(template, |caps: &Captures<'_>| {
            if err.is_some() {
                return String::new();
            }
            let token = &caps[1];
            if token == "secret" {
                return context.secret_text();
            }
            if let Some(rest) = token.strip_prefix("secret:") {
                let id = rest.trim();
                match context.get_referenced_secret(id) {
                    Some(val) => return val,
                    None => {
                        err = Some(OperationFailure::new(format!(
                            "Segredo referenciado nao autorizado: {id}"
                        )));
                        return String::new();
                    }
                }
            }
            if let Some(rest) = token.strip_prefix("param:") {
                let name = rest.trim();
                match context.get_parameter(name) {
                    Some(val) => return val.to_owned(),
                    None => {
                        err = Some(OperationFailure::new(format!(
                            "Parametro obrigatorio ausente: {name}"
                        )));
                        return String::new();
                    }
                }
            }
            String::new()
        });

        if let Some(failure) = err {
            return Err(failure);
        }

        Ok(replaced.into_owned())
    }

    #[cfg(feature = "http")]
    pub async fn execute_async(
        context: &OperationContext,
    ) -> Result<OperationOutcome, OperationFailure> {
        let start = Instant::now();
        let mut outcome = match context.operation.action.as_str() {
            Self::ACTION_NOOP_ECHO => Self::execute_echo(context),
            Self::ACTION_HTTP_REQUEST => Self::execute_http_async(context).await?,
            Self::ACTION_PROCESS_STDIN => {
                return Err(OperationFailure::new(
                    "Acoes de processo estao desabilitadas pelo contrato de seguranca atual.",
                ));
            }
            other => {
                return Err(OperationFailure::new(format!(
                    "Acao nao suportada: {other}"
                )));
            }
        };
        outcome.duration_ms = start.elapsed().as_millis().to_string();
        Ok(outcome)
    }

    pub fn execute_echo(context: &OperationContext) -> OperationOutcome {
        let payload = Zeroizing::new(format!("secret={}", context.secret_text()));
        OperationOutcome {
            kind: "echo".to_owned(),
            status_code: None,
            ok: true,
            body: Some(context.redactor.redact(&payload)),
            output: None,
            exit_code: None,
            duration_ms: "0".to_owned(),
        }
    }

    #[cfg(feature = "http")]
    async fn execute_http_async(
        context: &OperationContext,
    ) -> Result<OperationOutcome, OperationFailure> {
        use std::net::IpAddr;
        use std::time::Duration;
        use url::Url;

        let spec = context
            .operation
            .http
            .as_ref()
            .ok_or_else(|| OperationFailure::new("Operacao http.request sem especificacao."))?;

        if !TargetPolicy::are_equivalent_urls(&spec.url, &context.operation.target) {
            return Err(OperationFailure::new(
                "URL efetiva diferente do alvo autorizado.",
            ));
        }

        let uri = Url::parse(&spec.url)
            .map_err(|_| OperationFailure::new("URL da operacao invalida."))?;

        if !TargetPolicy::is_url(&spec.url) {
            return Err(OperationFailure::new("Alvo HTTP invalido."));
        }

        let is_loopback = match uri.host() {
            Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            None => uri
                .host_str()
                .and_then(|h| h.parse::<IpAddr>().ok())
                .is_some_and(|ip| ip.is_loopback()),
        };

        if !uri.scheme().eq_ignore_ascii_case("https") && !is_loopback {
            return Err(OperationFailure::new(
                "Somente HTTPS e loopback sao permitidos.",
            ));
        }

        let built_body = Self::build_body(spec, context)?;

        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| OperationFailure::new(format!("Falha ao preparar cliente HTTP: {e}")))?;

        let method = reqwest::Method::from_bytes(spec.method.trim().to_ascii_uppercase().as_bytes())
            .map_err(|_| OperationFailure::new("Metodo HTTP invalido."))?;

        let mut request = client.request(method, uri);
        if let Some((content_type, payload)) = built_body {
            request = request
                .header(reqwest::header::CONTENT_TYPE, content_type)
                .body(payload.to_vec());
        }

        for (name, template) in &spec.headers {
            let value = Zeroizing::new(Self::resolve_template(template, context)?);
            request = request.header(name.as_str(), value.as_str());
        }

        let response = request
            .send()
            .await
            .map_err(|e| OperationFailure::new(format!("Falha na requisicao HTTP: {e}")))?;

        let status = response.status();
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(|loc| context.redactor.redact(loc));

        let raw = response
            .text()
            .await
            .map_err(|e| OperationFailure::new(format!("Falha ao ler resposta HTTP: {e}")))?;

        let rendered = Self::select_result_fields(spec, &raw, &context.redactor)?;

        Ok(OperationOutcome {
            kind: "http".to_owned(),
            status_code: Some(status.as_u16() as i32),
            ok: status.is_success(),
            body: Some(rendered),
            output: location,
            exit_code: None,
            duration_ms: "0".to_owned(),
        })
    }

    #[cfg(feature = "http")]
    fn build_body(
        spec: &HttpRequestRecord,
        context: &OperationContext,
    ) -> Result<Option<(&'static str, Zeroizing<Vec<u8>>)>, OperationFailure> {
        if spec.body_fields.is_empty() {
            return Ok(None);
        }

        let mut resolved: BTreeMap<String, Zeroizing<String>> = BTreeMap::new();
        for (key, template) in &spec.body_fields {
            resolved.insert(
                key.clone(),
                Zeroizing::new(Self::resolve_template(template, context)?),
            );
        }

        let ct_lower = spec.content_type.to_ascii_lowercase();
        if ct_lower.contains("application/x-www-form-urlencoded") {
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            for (k, v) in &resolved {
                serializer.append_pair(k, v.as_str());
            }
            let encoded = Zeroizing::new(serializer.finish().into_bytes());
            return Ok(Some(("application/x-www-form-urlencoded", encoded)));
        }

        if ct_lower.contains("application/json") {
            let mut obj = Map::with_capacity(resolved.len());
            for (k, v) in &resolved {
                obj.insert(k.clone(), Value::String(v.as_str().to_owned()));
            }
            let bytes = serde_json::to_vec(&Value::Object(obj))
                .map_err(|_| OperationFailure::new("Falha ao serializar corpo JSON."))?;
            return Ok(Some((
                "application/json; charset=utf-8",
                Zeroizing::new(bytes),
            )));
        }

        Err(OperationFailure::new("Content-Type nao suportado."))
    }

    pub fn select_result_fields(
        spec: &HttpRequestRecord,
        raw: &str,
        redactor: &SecretRedactor,
    ) -> Result<String, OperationFailure> {
        if spec.result_fields.is_empty() {
            return Ok(redactor.redact(raw));
        }

        let parsed: Value = serde_json::from_str(raw).map_err(|_| {
            OperationFailure::new("A resposta nao permite aplicar a selecao de campos configurada.")
        })?;

        let mut selected = Map::new();
        if let Value::Object(root) = parsed {
            for field in &spec.result_fields {
                if let Some(val) = root.get(field) {
                    selected.insert(field.clone(), val.clone());
                }
            }
        }

        let serialized = serde_json::to_string(&Value::Object(selected)).map_err(|_| {
            OperationFailure::new("A resposta nao permite aplicar a selecao de campos configurada.")
        })?;
        Ok(redactor.redact(&serialized))
    }
}
