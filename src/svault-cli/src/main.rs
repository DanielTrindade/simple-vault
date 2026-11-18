use std::collections::{BTreeMap, HashMap};
use std::env;
use std::process::ExitCode;

use zeroize::Zeroizing;

use svault_client::secure_input::SecureInput;
use svault_client::{
    AuthorizeRequest, BrokerClient, BrokerError, HttpSpec, ProcessSpec, operation_statuses,
};
use svault_core::operations::OperationEngine;
use svault_core::storage::LsaRights;

enum CliFailure {
    Broker(BrokerError),
    Exit(u8, String),
}

impl From<BrokerError> for CliFailure {
    fn from(err: BrokerError) -> Self {
        Self::Broker(err)
    }
}

impl From<std::io::Error> for CliFailure {
    fn from(err: std::io::Error) -> Self {
        Self::Exit(3, err.to_string())
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        print_usage();
        return ExitCode::from(1);
    }

    let client = BrokerClient::from_env();
    match run(&client, &args) {
        Ok(code) => ExitCode::from(code),
        Err(CliFailure::Broker(err)) => {
            eprintln!("erro [{}]: {}", err.code, err.message);
            ExitCode::from(2)
        }
        Err(CliFailure::Exit(code, msg)) => {
            if !msg.is_empty() {
                eprintln!("{msg}");
            }
            ExitCode::from(code)
        }
    }
}

fn run(client: &BrokerClient, args: &[String]) -> Result<u8, CliFailure> {
    let command = args[0].to_ascii_lowercase();
    let options = Options::parse(&args[1..]);

    match command.as_str() {
        "health" => {
            let health = client.health()?;
            println!("status            : {}", health.status);
            println!("versao            : {}", health.version);
            println!("identidade        : {}", health.service_identity);
            println!("cofre inicializado: {}", health.vault_initialized);
            println!("totp ativo        : {}", health.totp_required);
            println!("registros         : {}", health.entry_count);
            println!("operacoes         : {}", health.operation_count);
            Ok(0)
        }
        "init" => {
            let passphrase = SecureInput::read_secret("Senha do cofre: ")?;
            if passphrase.chars().count() < 8 {
                return Err(CliFailure::Exit(
                    2,
                    "A senha do cofre precisa de pelo menos 8 caracteres.".to_owned(),
                ));
            }
            let confirm = SecureInput::read_secret("Confirme a senha: ")?;
            if *passphrase != *confirm {
                return Err(CliFailure::Exit(
                    2,
                    "As senhas nao conferem.".to_owned(),
                ));
            }
            let enable_totp = options.has("totp");
            let result = client.init_vault(&passphrase, enable_totp)?;
            println!("Cofre inicializado.");
            if enable_totp
                && let Some(uri) = result.totp_uri.filter(|u| !u.is_empty())
            {
                println!(
                    "Adicione este URI no seu aplicativo autenticador (uma unica vez):"
                );
                println!("{uri}");
            }
            Ok(0)
        }
        "list" => {
            let entries = client.list_entries()?;
            if entries.is_empty() {
                println!("(nenhum registro)");
                return Ok(0);
            }
            println!(
                "{:<28} {:<10} {:<40} ATUALIZADO",
                "IDENTIFICADOR", "TIPO", "ALVOS"
            );
            for entry in entries {
                let targets = entry.targets.join(", ");
                println!(
                    "{:<28} {:<10} {:<40} {}",
                    entry.id, entry.kind, targets, entry.updated_at
                );
            }
            Ok(0)
        }
        "ops" => {
            let operations = client.list_operations()?;
            if operations.is_empty() {
                println!("(nenhuma operacao)");
                return Ok(0);
            }
            println!(
                "{:<28} {:<22} {:<16} ALVO",
                "OPERACAO", "REGISTRO", "ACAO"
            );
            for op in operations {
                println!(
                    "{:<28} {:<22} {:<16} {}",
                    op.id, op.entry_id, op.action, op.target
                );
            }
            Ok(0)
        }
        "add" => {
            let id = options.require("id")?;
            let kind = options.opt("kind", "generic");
            let label = options.opt("label", &id);
            let targets = options.split_list_required("target")?;
            let value = SecureInput::read_secret("Valor do segredo: ")?;
            let passphrase = SecureInput::read_secret("Senha do cofre: ")?;

            let entry = client.register_entry(&id, &kind, &label, &targets, &value, &passphrase)?;
            println!(
                "Registro {} cadastrado (revisao {}).",
                entry.id, entry.revision
            );
            Ok(0)
        }
        "update" => {
            let id = options.require("id")?;
            let passphrase = SecureInput::read_secret("Senha do cofre: ")?;
            let value: Option<Zeroizing<String>> = if options.has("value") {
                Some(SecureInput::read_secret("Novo valor: ")?)
            } else {
                None
            };
            let label = options.opt_nullable("label");
            let targets = if options.has("target") {
                Some(options.split_list("target"))
            } else {
                None
            };

            let entry = client.update_entry(
                &id,
                value.as_deref().map(String::as_str),
                label.as_deref(),
                targets.as_deref(),
                &passphrase,
            )?;
            println!(
                "Registro {} atualizado (revisao {}).",
                entry.id, entry.revision
            );
            Ok(0)
        }
        "remove" => {
            let id = options.require("id")?;
            let passphrase = SecureInput::read_secret("Senha do cofre: ")?;
            client.delete_entry(&id, &passphrase)?;
            println!("Registro {id} removido.");
            Ok(0)
        }
        "authorize" => {
            let id = options.require("id")?;
            let entry_id = options.require("entry")?;
            let action = options.require("action")?;
            let target = options.require("target")?;
            let description = options.opt("description", "");
            let param_names = options.split_list("param");
            let passphrase = SecureInput::read_secret("Senha do cofre: ")?;

            let mut req = AuthorizeRequest {
                id,
                entry_id,
                action: action.clone(),
                target: target.clone(),
                description,
                params: param_names,
                http: None,
                process: None,
            };

            if action == OperationEngine::ACTION_HTTP_REQUEST {
                req.http = Some(HttpSpec {
                    method: options.opt("method", "POST"),
                    url: target,
                    content_type: options.opt("content-type", "application/json"),
                    body_fields: options.parse_map("body"),
                    headers: options.parse_map("header"),
                    result_fields: options.split_list("result-field"),
                });
            } else if action == OperationEngine::ACTION_PROCESS_STDIN {
                let timeout_seconds = options
                    .opt("timeout", "30")
                    .parse::<i32>()
                    .unwrap_or(30);
                req.process = Some(ProcessSpec {
                    executable: target,
                    args: options.split_list("arg"),
                    env: options.split_list("env"),
                    timeout_seconds,
                });
            }

            let operation = client.authorize_operation(&req, &passphrase)?;
            println!(
                "Operacao {} autorizada para {} -> {}",
                operation.id, operation.entry_id, operation.target
            );
            Ok(0)
        }
        "revoke" => {
            let id = options.require("id")?;
            let passphrase = SecureInput::read_secret("Senha do cofre: ")?;
            client.revoke_operation(&id, &passphrase)?;
            println!("Operacao {id} revogada.");
            Ok(0)
        }
        "request" => {
            let op_id = options.require("op")?;
            let parameters = options.parse_map("param-value");
            let result = client.request_operation(&op_id, Some(&parameters))?;
            println!("requestId : {}", result.request_id);
            println!("status    : {}", result.status);
            println!("requer    : {}", result.requires);
            println!("expira em : {}", result.expires_at);
            println!(
                "operacao  : {} -> {}",
                result.summary.operation_id, result.summary.target
            );
            Ok(0)
        }
        "pending" => {
            let pending = client.pending_approvals()?;
            if pending.is_empty() {
                println!("(nenhuma solicitacao pendente)");
                return Ok(0);
            }
            for request in pending {
                let parameters = request
                    .summary
                    .parameters
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                let method_or_action = request
                    .summary
                    .method
                    .as_deref()
                    .unwrap_or(&request.summary.action);
                println!(
                    "{}  {}  {}  {}  {}  [{}]  expira {}",
                    request.request_id,
                    request.summary.operation_id,
                    request.summary.entry_id,
                    method_or_action,
                    request.summary.target,
                    parameters,
                    request.expires_at
                );
            }
            Ok(0)
        }
        "approve" => {
            let request_id = options.require("request")?;
            let passphrase = SecureInput::read_secret("Senha do cofre: ")?;
            let totp_opt: Option<Zeroizing<String>> =
                if let Some(provided) = options.opt_nullable("totp") {
                    Some(Zeroizing::new(provided))
                } else {
                    let entered = SecureInput::read_secret("Codigo TOTP (se ativo): ")?;
                    if entered.trim().is_empty() {
                        None
                    } else {
                        Some(entered)
                    }
                };

            let result = client.approve(
                &request_id,
                &passphrase,
                totp_opt.as_deref().map(String::as_str),
            )?;
            let status_str = result.status.as_deref().unwrap_or("");
            println!("status : {status_str}");
            if let Some(outcome) = &result.result
                && let Ok(json) = serde_json::to_string(outcome)
            {
                println!("resultado: {json}");
            }
            if let Some(error) = &result.error {
                println!("erro    : {error}");
            }

            let ok = status_str == operation_statuses::COMPLETED
                && result.result.as_ref().is_some_and(|r| r.ok);
            Ok(if ok { 0 } else { 4 })
        }
        "reject" => {
            let request_id = options.require("request")?;
            let passphrase = SecureInput::read_secret("Senha do cofre: ")?;
            client.reject(&request_id, &passphrase)?;
            println!("Solicitacao rejeitada.");
            Ok(0)
        }
        "status" => {
            let request_id = options.require("request")?;
            let status = client.operation_status(&request_id)?;
            println!("status    : {}", status.status);
            println!("operacao  : {}", status.summary.operation_id);
            println!("alvo      : {}", status.summary.target);
            if let Some(outcome) = &status.result
                && let Ok(json) = serde_json::to_string(outcome)
            {
                println!("resultado : {json}");
            }
            if let Some(error) = &status.error {
                println!("erro      : {error}");
            }

            let ok = status.status == operation_statuses::COMPLETED
                && status.result.as_ref().is_some_and(|r| r.ok);
            Ok(if ok { 0 } else { 4 })
        }
        "set-totp" => {
            let secret = Zeroizing::new(
                options
                    .require("secret")?
                    .replace(' ', "")
                    .to_ascii_uppercase(),
            );
            let passphrase = SecureInput::read_secret("Senha do cofre: ")?;
            let admin_totp = read_admin_totp(client, &options)?;
            client.set_totp(
                &secret,
                &passphrase,
                admin_totp.as_deref().map(String::as_str),
            )?;
            println!("TOTP ativado.");
            Ok(0)
        }
        "disable-totp" => {
            let passphrase = SecureInput::read_secret("Senha do cofre: ")?;
            let admin_totp = read_admin_totp(client, &options)?;
            client.disable_totp(&passphrase, admin_totp.as_deref().map(String::as_str))?;
            println!("TOTP desativado.");
            Ok(0)
        }
        "change-passphrase" => {
            let current = SecureInput::read_secret("Senha atual: ")?;
            let next = SecureInput::read_secret("Nova senha: ")?;
            let confirm = SecureInput::read_secret("Confirme a nova senha: ")?;
            if *next != *confirm {
                return Err(CliFailure::Exit(
                    2,
                    "As senhas nao conferem.".to_owned(),
                ));
            }
            let admin_totp = read_admin_totp(client, &options)?;
            client.change_passphrase(
                &current,
                &next,
                admin_totp.as_deref().map(String::as_str),
            )?;
            println!("Senha do cofre alterada.");
            Ok(0)
        }
        "admin" => run_admin(&options),
        "reset" => {
            let passphrase = SecureInput::read_secret("Senha do cofre: ")?;
            let admin_totp = read_admin_totp(client, &options)?;
            let result =
                client.reset_vault(&passphrase, admin_totp.as_deref().map(String::as_str))?;
            println!(
                "Cofre reiniciado. {} registro(s) removido(s).",
                result.entries_removed
            );
            println!("Use 'svaultctl init --totp' para definir uma nova senha do cofre.");
            Ok(0)
        }
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(0)
        }
        other => {
            eprintln!("Comando desconhecido: {other}");
            print_usage();
            Ok(1)
        }
    }
}

fn run_admin(options: &Options) -> Result<u8, CliFailure> {
    let action = options.opt("action", "setup-service-account");
    let account = options.opt("account", "svault_svc");
    let machine = env::var("COMPUTERNAME").unwrap_or_else(|_| ".".to_owned());
    let account_name = if account.contains('\\') {
        account.clone()
    } else {
        format!("{machine}\\{account}")
    };

    let sid = match LsaRights::resolve_account_sid(&account_name) {
        Ok(s) => s,
        Err(_) => {
            return Err(CliFailure::Exit(
                1,
                format!("Nao foi possivel resolver a conta {account}."),
            ));
        }
    };

    match action.as_str() {
        "setup-service-account" => {
            LsaRights::grant(&sid, &[LsaRights::SE_SERVICE_LOGON_RIGHT])
                .map_err(|e| CliFailure::Exit(3, format!("erro: {e}")))?;
            LsaRights::grant(
                &sid,
                &[
                    LsaRights::SE_DENY_INTERACTIVE_LOGON_RIGHT,
                    LsaRights::SE_DENY_REMOTE_INTERACTIVE_LOGON_RIGHT,
                    LsaRights::SE_DENY_NETWORK_LOGON_RIGHT,
                ],
            )
            .map_err(|e| CliFailure::Exit(3, format!("erro: {e}")))?;

            println!("Direitos aplicados para {account} ({sid}):");
            println!("  permitido : {}", LsaRights::SE_SERVICE_LOGON_RIGHT);
            println!(
                "  negado    : {}, {}, {}",
                LsaRights::SE_DENY_INTERACTIVE_LOGON_RIGHT,
                LsaRights::SE_DENY_REMOTE_INTERACTIVE_LOGON_RIGHT,
                LsaRights::SE_DENY_NETWORK_LOGON_RIGHT
            );
            Ok(0)
        }
        other => Err(CliFailure::Exit(
            1,
            format!("Acao administrativa desconhecida: {other}"),
        )),
    }
}

fn read_admin_totp(
    client: &BrokerClient,
    options: &Options,
) -> Result<Option<Zeroizing<String>>, CliFailure> {
    if let Some(provided) = options.opt_nullable("totp") {
        return Ok(Some(Zeroizing::new(provided)));
    }
    if client.health()?.totp_required {
        Ok(Some(SecureInput::read_secret("Codigo TOTP atual: ")?))
    } else {
        Ok(None)
    }
}

struct Options {
    values: HashMap<String, Vec<String>>,
}

impl Options {
    fn parse(args: &[String]) -> Self {
        let mut values: HashMap<String, Vec<String>> = HashMap::new();
        let mut i = 0;
        while i < args.len() {
            let Some(raw_key) = args[i].strip_prefix("--") else {
                i += 1;
                continue;
            };
            let key = raw_key.to_ascii_lowercase();
            let val = if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                i += 1;
                args[i].clone()
            } else {
                "true".to_owned()
            };
            values.entry(key).or_default().push(val);
            i += 1;
        }
        Self { values }
    }

    fn has(&self, key: &str) -> bool {
        self.values.contains_key(&key.to_ascii_lowercase())
    }

    fn last_non_empty(&self, key: &str) -> Option<&str> {
        self.values
            .get(&key.to_ascii_lowercase())
            .and_then(|list| list.iter().rev().find(|v| !v.trim().is_empty()))
            .map(String::as_str)
    }

    fn opt(&self, key: &str, fallback: &str) -> String {
        self.last_non_empty(key).unwrap_or(fallback).to_owned()
    }

    fn opt_nullable(&self, key: &str) -> Option<String> {
        self.last_non_empty(key).map(str::to_owned)
    }

    fn require(&self, key: &str) -> Result<String, CliFailure> {
        self.opt_nullable(key).ok_or_else(|| {
            CliFailure::Exit(3, format!("erro: Opcao obrigatoria ausente: --{key}"))
        })
    }

    fn split_list(&self, key: &str) -> Vec<String> {
        let Some(entries) = self.values.get(&key.to_ascii_lowercase()) else {
            return Vec::new();
        };
        entries
            .iter()
            .flat_map(|v| v.split(','))
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect()
    }

    fn split_list_required(&self, key: &str) -> Result<Vec<String>, CliFailure> {
        let _ = self.require(key)?;
        Ok(self.split_list(key))
    }

    fn parse_map(&self, key: &str) -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        let Some(entries) = self.values.get(&key.to_ascii_lowercase()) else {
            return map;
        };
        for item in entries {
            for pair in item.split([',', '\n']) {
                let trimmed = pair.trim();
                let Some((k, v)) = trimmed.split_once('=') else {
                    continue;
                };
                let k = k.trim();
                if !k.is_empty() {
                    map.insert(k.to_owned(), v.trim().to_owned());
                }
            }
        }
        map
    }
}

fn print_usage() {
    println!(
        r#"svaultctl - gerenciamento do cofre SVault (somente para o proprietario)

Uso: svaultctl <comando> [opcoes]

Comandos:
  health                                   situacao do broker e do cofre
  init [--totp]                            inicializa o cofre e define a senha do cofre
  list                                     lista identificadores e metadados (nunca valores)
  ops                                      lista operacoes autorizadas
  add --id ID --target ALVO [--kind K] [--label L]
                                         cadastra um segredo (o valor e lido sem eco)
  update --id ID [--value] [--label L] [--target ALVO]
                                         atualiza um segredo
  remove --id ID                           remove um segredo
  authorize --id OP --entry ENTRY --action ACAO --target ALVO
           [--param NOME] [--body k=v] [--header k=v] [--method M]
                                         autoriza uma operacao pre-definida
  revoke --id OP                           revoga uma operacao
  request --op OP [--param-value k=v]      solicita uma operacao (aguarda aprovacao)
  pending                                  lista solicitacoes aguardando aprovacao
  approve --request ID [--totp CODIGO]     aprova e executa (exige a senha do cofre)
  reject --request ID                      rejeita uma solicitacao
  status --request ID                      mostra o resultado sanitizado
  set-totp --secret BASE32 [--totp CODIGO] ativa ou substitui o TOTP
  disable-totp [--totp CODIGO]             desativa o TOTP
  change-passphrase [--totp CODIGO]        troca a senha do cofre
  reset [--totp CODIGO]                    reinicia o cofre e apaga todos os segredos
  admin --action setup-service-account --account NOME
                                         concede "Log on as a service" via API LSA
                                         (necessario so se o broker rodar com conta dedicada)

Observacao: a senha do cofre e sempre digitada interativamente, sem eco e sem area de transferencia."#
    );
}
