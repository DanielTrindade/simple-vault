use std::collections::BTreeMap;
use std::env;
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::json;
use svault_client::{AuthorizeRequest, BrokerClient, HttpSpec};

const PASSPHRASE: &str = "senha-ficticia-do-cofre";
const CPF_FAKE: &str = "529.982.247-25";
const SENHA_FAKE: &str = "SenhaFicticia!2026";

struct FakeHttpServer {
    port: u16,
    received_bodies: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
}

impl FakeHttpServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake http");
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();

        let received_bodies = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let bodies_clone = Arc::clone(&received_bodies);
        let stop_clone = Arc::clone(&stop);

        thread::spawn(move || {
            while !stop_clone.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                        let mut buf = [0u8; 16384];
                        if let Ok(n) = stream.read(&mut buf)
                            && n > 0
                        {
                            let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                            let body = req
                                .split_once("\r\n\r\n")
                                .map(|(_, b)| b.to_owned())
                                .unwrap_or_default();
                            bodies_clone.lock().unwrap().push(body.clone());
                            let resp_body =
                                serde_json::to_string(&json!({ "status": "ok", "echo": body }))
                                    .unwrap();
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                resp_body.len(),
                                resp_body
                            );
                            let _ = stream.write_all(resp.as_bytes());
                            let _ = stream.flush();
                        }
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            port,
            received_bodies,
            stop,
        }
    }

    fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

impl Drop for FakeHttpServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if !args
        .iter()
        .any(|a| a.eq_ignore_ascii_case("--allow-installed-broker"))
    {
        eprintln!(
            "Esta demonstracao conecta ao broker instalado. Use --allow-installed-broker para autorizar explicitamente."
        );
        return ExitCode::from(2);
    }

    let keep = args.iter().any(|a| a.eq_ignore_ascii_case("--keep"));
    let client = BrokerClient::from_env();

    if args.len() >= 2 && args[0] == "approve" {
        match client.approve(&args[1], PASSPHRASE, None) {
            Ok(approved) => {
                println!("status: {}", approved.status.unwrap_or_default());
                if let Some(res) = approved.result {
                    println!("{}", serde_json::to_string(&res).unwrap());
                }
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                eprintln!("erro [{}]: {}", e.code, e.message);
                return ExitCode::from(1);
            }
        }
    }

    if !args.is_empty() && args[0] == "reset" {
        match client.reset_vault(PASSPHRASE, None) {
            Ok(reset) => {
                println!(
                    "cofre reiniciado ({} registro removido).",
                    reset.entries_removed
                );
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                eprintln!("erro [{}]: {}", e.code, e.message);
                return ExitCode::from(1);
            }
        }
    }

    match run_demo(&client, keep) {
        Ok(leaked) => {
            if leaked {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(e) => {
            eprintln!("erro: {e}");
            ExitCode::from(1)
        }
    }
}

fn run_demo(client: &BrokerClient, keep: bool) -> Result<bool, String> {
    let server = FakeHttpServer::start();

    println!("=== SVault: demonstracao com dados ficticios ===");
    println!();

    let health = client.health().map_err(|e| e.to_string())?;
    println!(
        "[1] broker ativo: {} | identidade {} | cofre inicializado: {}",
        health.status, health.service_identity, health.vault_initialized
    );

    if !health.vault_initialized {
        client
            .init_vault(PASSPHRASE, false)
            .map_err(|e| e.to_string())?;
        println!("[2] cofre inicializado com senha ficticia");
    } else {
        println!("[2] cofre ja inicializado (usando a senha de teste)");
    }

    let targets = vec![server.base_url()];
    client
        .register_entry(
            "CPF_PESSOAL",
            "cpf",
            "CPF pessoal (FICTICIO)",
            &targets,
            CPF_FAKE,
            PASSPHRASE,
        )
        .map_err(|e| e.to_string())?;
    client
        .register_entry(
            "SENHA_PORTAL_A",
            "password",
            "Senha do portal A (FICTICIA)",
            &targets,
            SENHA_FAKE,
            PASSPHRASE,
        )
        .map_err(|e| e.to_string())?;

    println!("[3] segredos ficticios cadastrados: CPF_PESSOAL, SENHA_PORTAL_A");

    let login_url = format!("{}/api/login", server.base_url());
    let mut body_fields = BTreeMap::new();
    body_fields.insert("usuario".into(), "{{param:usuario}}".into());
    body_fields.insert("senha".into(), "{{secret}}".into());
    client
        .authorize_operation(
            &AuthorizeRequest {
                id: "login_portal_a".into(),
                entry_id: "SENHA_PORTAL_A".into(),
                action: "http.request".into(),
                target: login_url.clone(),
                description: "Autenticacao ficticia no portal A".into(),
                params: vec!["usuario".into()],
                http: Some(HttpSpec {
                    method: "POST".into(),
                    url: login_url,
                    content_type: "application/json".into(),
                    body_fields,
                    headers: BTreeMap::new(),
                    result_fields: Vec::new(),
                }),
                process: None,
            },
            PASSPHRASE,
        )
        .map_err(|e| e.to_string())?;

    client
        .authorize_operation(
            &AuthorizeRequest {
                id: "eco_cpf".into(),
                entry_id: "CPF_PESSOAL".into(),
                action: "noop.echo".into(),
                target: "eco".into(),
                description: "Diagnostico de redacao (sem rede)".into(),
                params: Vec::new(),
                http: None,
                process: None,
            },
            PASSPHRASE,
        )
        .map_err(|e| e.to_string())?;

    println!("[4] operacoes autorizadas: login_portal_a (http.request), eco_cpf (noop.echo)");
    println!();

    println!("--- visao do AGENTE (via MCP: list_entries / list_operations) ---");
    let entries = client.list_entries().map_err(|e| e.to_string())?;
    println!("{}", serde_json::to_string(&json!({ "entries": entries })).unwrap());
    let operations = client.list_operations().map_err(|e| e.to_string())?;
    println!(
        "{}",
        serde_json::to_string(&json!({ "operations": operations })).unwrap()
    );
    println!();

    println!("--- AGENTE solicita a operacao ---");
    let mut params = BTreeMap::new();
    params.insert("usuario".into(), "usuario-ficticio".into());
    let request = client
        .request_operation("login_portal_a", Some(&params))
        .map_err(|e| e.to_string())?;
    println!("{}", serde_json::to_string(&request).unwrap());
    println!("(status pendente: o agente NAO recebe o segredo e NAO pode executar ainda)");
    println!();

    println!("--- DONO aprova (senha do cofre) ---");
    let approval = client
        .approve(&request.request_id, PASSPHRASE, None)
        .map_err(|e| e.to_string())?;
    println!("status: {}", approval.status.unwrap_or_default());
    println!();

    println!("--- visao do AGENTE apos a execucao (via MCP: operation_status) ---");
    let status = client
        .operation_status(&request.request_id)
        .map_err(|e| e.to_string())?;
    let rendered = serde_json::to_string(&status).unwrap();
    println!("{rendered}");
    println!();

    println!("--- o portal ficticio recebeu o segredo de verdade? ---");
    for body in server.received_bodies.lock().unwrap().iter() {
        println!("  servidor ficticio recebeu: {body}");
    }
    println!();

    let leaked = rendered.contains(SENHA_FAKE) || rendered.contains(CPF_FAKE);
    println!(
        "[5] o valor do segredo apareceu na resposta ao agente? {}",
        if leaked {
            "SIM (FALHA)"
        } else {
            "NAO (correto)"
        }
    );
    println!(
        "[6] a resposta ao agente contem a mascara: {}",
        if rendered.contains("***REDACTED***") {
            "SIM (correto)"
        } else {
            "NAO"
        }
    );

    println!();
    if !keep {
        println!("--- limpando o cofre de teste ---");
        let reset = client
            .reset_vault(PASSPHRASE, None)
            .map_err(|e| e.to_string())?;
        println!(
            "cofre reiniciado ({} registro removido). Use 'svaultctl init --totp' para criar o seu.",
            reset.entries_removed
        );
    } else {
        println!("--- cofre de teste mantido (--keep) ---");
    }

    println!();
    Ok(leaked)
}
