use std::collections::BTreeMap;

use chrono::{DateTime, Local, Utc};

use crate::broker::{AuthorizeRequest, Entry, HttpSpec, Operation, PendingRequest, ProcessSpec};

pub const ENTRY_KINDS: [&str; 4] = ["cpf", "password", "token", "generic"];
pub const ACTIONS: [&str; 3] = ["http.request", "process.stdin", "noop.echo"];
pub const METHODS: [&str; 5] = ["GET", "POST", "PUT", "PATCH", "DELETE"];

pub fn kind_label(kind: &str) -> &'static str {
    match kind {
        "cpf" => "CPF",
        "password" => "Senha",
        "token" => "Token",
        _ => "Genérico",
    }
}

pub fn action_label(action: &str) -> &'static str {
    match action {
        "http.request" => "HTTP",
        "process.stdin" => "Processo",
        "noop.echo" => "Eco",
        _ => "Outra",
    }
}

fn parse_time(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value).ok().map(|t| t.with_timezone(&Utc))
}

pub fn format_time(value: &str) -> String {
    match parse_time(value) {
        Some(time) => time.with_timezone(&Local).format("%d/%m/%Y %H:%M").to_string(),
        None => value.to_owned(),
    }
}

pub struct Countdown {
    pub text: String,
    pub progress: f32,
    pub urgent: bool,
}

pub fn countdown(created: &str, expires: &str, now: DateTime<Utc>) -> Countdown {
    let (Some(created), Some(expires)) = (parse_time(created), parse_time(expires)) else {
        return Countdown { text: "—".into(), progress: 1.0, urgent: false };
    };
    let remaining = (expires - now).num_seconds().max(0);
    let total = (expires - created).num_seconds().max(1);
    let text = if remaining == 0 {
        "expirando".to_owned()
    } else if remaining >= 3600 {
        format!("{}h{:02}", remaining / 3600, (remaining % 3600) / 60)
    } else {
        format!("{}:{:02}", remaining / 60, remaining % 60)
    };
    Countdown { text, progress: remaining as f32 / total as f32, urgent: remaining < 60 }
}

pub fn matches(query: &str, fields: &[&str]) -> bool {
    let query = fold(query.trim());
    query.is_empty() || fields.iter().any(|field| fold(field).contains(&query))
}

pub fn fold(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            'á' | 'à' | 'â' | 'ã' | 'Á' | 'À' | 'Â' | 'Ã' => 'a',
            'é' | 'ê' | 'É' | 'Ê' => 'e',
            'í' | 'Í' => 'i',
            'ó' | 'ô' | 'õ' | 'Ó' | 'Ô' | 'Õ' => 'o',
            'ú' | 'Ú' => 'u',
            'ç' | 'Ç' => 'c',
            other => other.to_ascii_lowercase(),
        })
        .collect()
}

pub fn entry_matches(entry: &Entry, query: &str) -> bool {
    let targets = entry.targets.join(" ");
    matches(query, &[&entry.id, &entry.label, &targets, kind_label(&entry.kind)])
}

pub fn operation_matches(operation: &Operation, query: &str) -> bool {
    matches(query, &[&operation.id, &operation.entry_id, &operation.target, &operation.description, &operation.action])
}

pub fn request_label(request: &PendingRequest) -> String {
    let summary = &request.summary;
    match (&summary.method, summary.action.as_str()) {
        (Some(method), "http.request") => format!("HTTP {method}"),
        _ => action_label(&summary.action).to_owned(),
    }
}

pub fn lines(text: &str) -> Vec<String> {
    text.lines().map(str::trim).filter(|l| !l.is_empty()).map(str::to_owned).collect()
}

pub fn comma_list(text: &str) -> Vec<String> {
    text.split(',').map(str::trim).filter(|l| !l.is_empty()).map(str::to_owned).collect()
}

pub fn key_values(text: &str) -> BTreeMap<String, String> {
    lines(text)
        .into_iter()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            let key = key.trim();
            (!key.is_empty()).then(|| (key.to_owned(), value.trim().to_owned()))
        })
        .collect()
}

pub struct AuthorizeInput<'a> {
    pub id: &'a str,
    pub entry_id: &'a str,
    pub description: &'a str,
    pub params: &'a str,
    pub action: usize,
    pub target: &'a str,
    pub method: usize,
    pub content_type: &'a str,
    pub body: &'a str,
    pub headers: &'a str,
    pub result_fields: &'a str,
    pub args: &'a str,
    pub env: &'a str,
    pub timeout: &'a str,
}

pub fn build_authorize(input: &AuthorizeInput) -> Result<AuthorizeRequest, String> {
    let id = input.id.trim();
    let target = input.target.trim();
    if id.is_empty() {
        return Err("Informe o identificador da operação.".into());
    }
    if input.entry_id.is_empty() {
        return Err("Escolha o segredo que a operação vai usar.".into());
    }
    if target.is_empty() {
        return Err("Informe o alvo da operação.".into());
    }

    let action = ACTIONS.get(input.action).copied().unwrap_or(ACTIONS[0]);
    let mut request = AuthorizeRequest {
        id: id.to_owned(),
        entry_id: input.entry_id.to_owned(),
        action: action.to_owned(),
        target: target.to_owned(),
        description: input.description.trim().to_owned(),
        params: comma_list(input.params),
        ..Default::default()
    };

    match action {
        "http.request" => {
            let content_type = input.content_type.trim();
            request.http = Some(HttpSpec {
                method: METHODS.get(input.method).copied().unwrap_or("POST").to_owned(),
                url: target.to_owned(),
                content_type: if content_type.is_empty() { "application/json".into() } else { content_type.to_owned() },
                body_fields: key_values(input.body),
                headers: key_values(input.headers),
                result_fields: comma_list(input.result_fields),
            });
        }
        "process.stdin" => {
            let timeout = input.timeout.trim();
            let timeout_seconds = if timeout.is_empty() {
                30
            } else {
                timeout.parse::<i32>().ok().filter(|t| *t > 0).ok_or("O tempo limite precisa ser um número de segundos.")?
            };
            request.process = Some(ProcessSpec {
                executable: target.to_owned(),
                args: lines(input.args),
                env: lines(input.env),
                timeout_seconds,
            });
        }
        _ => {}
    }

    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn input<'a>(action: usize) -> AuthorizeInput<'a> {
        AuthorizeInput {
            id: " login_rh ",
            entry_id: "SENHA_RH",
            description: "",
            params: "usuario, competencia,",
            action,
            target: "https://rh.exemplo/login",
            method: 1,
            content_type: "",
            body: "password={{secret}}\nuser = {{param:usuario}}\nlixo",
            headers: "",
            result_fields: "status",
            args: "--login\n\n--quiet",
            env: "MODO=ci",
            timeout: "",
        }
    }

    #[test]
    fn http_operation_parses_body_and_defaults_content_type() {
        let request = build_authorize(&input(0)).unwrap();
        assert_eq!(request.id, "login_rh");
        assert_eq!(request.params, vec!["usuario", "competencia"]);
        let http = request.http.unwrap();
        assert_eq!(http.method, "POST");
        assert_eq!(http.content_type, "application/json");
        assert_eq!(http.body_fields["user"], "{{param:usuario}}");
        assert_eq!(http.body_fields.len(), 2);
        assert!(request.process.is_none());
    }

    #[test]
    fn process_operation_uses_target_as_executable() {
        let request = build_authorize(&input(1)).unwrap();
        let process = request.process.unwrap();
        assert_eq!(process.executable, "https://rh.exemplo/login");
        assert_eq!(process.args, vec!["--login", "--quiet"]);
        assert_eq!(process.timeout_seconds, 30);
        assert!(request.http.is_none());
    }

    #[test]
    fn invalid_timeout_is_rejected() {
        let mut data = input(1);
        data.timeout = "abc";
        assert!(build_authorize(&data).is_err());
    }

    #[test]
    fn countdown_reports_remaining_fraction() {
        let now = Utc.with_ymd_and_hms(2026, 10, 20, 10, 2, 30).unwrap();
        let c = countdown("2026-10-20T10:00:00Z", "2026-10-20T10:05:00+00:00", now);
        assert_eq!(c.text, "2:30");
        assert!((c.progress - 0.5).abs() < 0.01);
        assert!(!c.urgent);
        let late = countdown("2026-10-20T10:00:00Z", "2026-10-20T10:02:50.1234567Z", now);
        assert!(late.urgent);
    }

    #[test]
    fn search_ignores_case_and_accents() {
        assert!(matches("operacao", &["Operação de login"]));
        assert!(matches("", &["x"]));
        assert!(!matches("token", &["SENHA"]));
    }
}
