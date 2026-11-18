use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use chrono::Utc;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use svault_broker::engine::BrokerEngine;
use svault_client::{AuthorizeRequest, BrokerClient, BrokerError, HttpSpec};
use svault_core::config::BrokerConfig;
use svault_core::crypto::{Totp, VaultCrypto};
use svault_core::logging::VaultLog;
use svault_core::operations::{OperationContext, OperationEngine};
use svault_core::protocol::{Envelope, OperationRequestResult};
use svault_core::redaction::{MASK, SecretRedactor};
use svault_core::storage::{
    CredentialStore, HttpRequestRecord, MemoryCredentialStore, OperationRecord, ProcessRecord,
    TargetPolicy, VaultError, VaultState, VaultStore,
};

const PASSPHRASE: &str = "senha-de-teste-2026";
const CPF_FAKE: &str = "529.982.247-25";
const SENHA_FAKE: &str = "S3nh@Ficticia-2026!";

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
                        handle_http(&mut stream, &bodies_clone);
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

    fn bodies(&self) -> Vec<String> {
        self.received_bodies.lock().unwrap().clone()
    }
}

impl Drop for FakeHttpServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn handle_http(stream: &mut std::net::TcpStream, received: &Mutex<Vec<String>>) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let header_end;
    loop {
        let Ok(n) = stream.read(&mut chunk) else {
            return;
        };
        if n == 0 {
            return;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = pos;
            break;
        }
        if buf.len() > 64 * 1024 {
            return;
        }
    }

    let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let mut body_bytes = buf[header_end + 4..].to_vec();

    let content_length = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            if k.trim().eq_ignore_ascii_case("content-length") {
                v.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);

    while body_bytes.len() < content_length {
        let Ok(n) = stream.read(&mut chunk) else {
            break;
        };
        if n == 0 {
            break;
        }
        body_bytes.extend_from_slice(&chunk[..n]);
    }

    let body = String::from_utf8_lossy(&body_bytes[..body_bytes.len().min(content_length)])
        .into_owned();
    received.lock().unwrap().push(body.clone());

    let response_body = if head.contains("/invalid-json") {
        "raw-invalid-secret".to_owned()
    } else {
        serde_json::to_string(&json!({
            "status": "ok",
            "echo": body,
        }))
        .unwrap()
    };

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        response_body.len(),
        response_body
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

struct CountingCredentialStore {
    inner: MemoryCredentialStore,
    reads: AtomicUsize,
}

impl CountingCredentialStore {
    fn new() -> Self {
        Self {
            inner: MemoryCredentialStore::new(),
            reads: AtomicUsize::new(0),
        }
    }

    fn read_count(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }

    fn reset_read_count(&self) {
        self.reads.store(0, Ordering::SeqCst);
    }
}

impl CredentialStore for CountingCredentialStore {
    fn write(&self, target: &str, user_name: &str, secret: &[u8]) -> io::Result<()> {
        self.inner.write(target, user_name, secret)
    }

    fn read(&self, target: &str) -> io::Result<Option<Vec<u8>>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.inner.read(target)
    }

    fn delete(&self, target: &str) -> io::Result<()> {
        self.inner.delete(target)
    }

    fn list_targets(&self, filter: &str) -> io::Result<Vec<String>> {
        self.inner.list_targets(filter)
    }
}

struct FailingState {
    writes: usize,
    reads: usize,
    fail_write: Option<usize>,
    fail_read: Option<usize>,
    after_write: Option<Box<dyn FnMut(usize) + Send>>,
}

struct FailingCredentialStore {
    inner: MemoryCredentialStore,
    state: Mutex<FailingState>,
}

impl FailingCredentialStore {
    fn new() -> Self {
        Self {
            inner: MemoryCredentialStore::new(),
            state: Mutex::new(FailingState {
                writes: 0,
                reads: 0,
                fail_write: None,
                fail_read: None,
                after_write: None,
            }),
        }
    }

    fn fail_on_write(&self, num: Option<usize>) {
        let mut s = self.state.lock().unwrap();
        s.writes = 0;
        s.reads = 0;
        s.fail_write = num;
        s.fail_read = None;
    }

    fn fail_on_read(&self, num: Option<usize>) {
        let mut s = self.state.lock().unwrap();
        s.reads = 0;
        s.fail_read = num;
    }

    fn set_after_write(&self, hook: Option<Box<dyn FnMut(usize) + Send>>) {
        let mut s = self.state.lock().unwrap();
        s.after_write = hook;
    }
}

impl CredentialStore for FailingCredentialStore {
    fn write(&self, target: &str, user_name: &str, secret: &[u8]) -> io::Result<()> {
        let mut s = self.state.lock().unwrap();
        s.writes += 1;
        let current = s.writes;
        if Some(current) == s.fail_write {
            return Err(io::Error::other("falha de armazenamento sintetica"));
        }
        self.inner.write(target, user_name, secret)?;
        if let Some(hook) = s.after_write.as_mut() {
            hook(current);
        }
        Ok(())
    }

    fn read(&self, target: &str) -> io::Result<Option<Vec<u8>>> {
        let mut s = self.state.lock().unwrap();
        s.reads += 1;
        if Some(s.reads) == s.fail_read {
            return Err(io::Error::other("falha sintetica de leitura"));
        }
        self.inner.read(target)
    }

    fn delete(&self, target: &str) -> io::Result<()> {
        self.inner.delete(target)
    }

    fn list_targets(&self, filter: &str) -> io::Result<Vec<String>> {
        self.inner.list_targets(filter)
    }
}

struct Runner {
    passed: usize,
    failed: usize,
}

impl Runner {
    fn new() -> Self {
        Self {
            passed: 0,
            failed: 0,
        }
    }

    fn test(&mut self, name: &str, f: impl FnOnce() -> Result<(), String>) {
        match f() {
            Ok(()) => {
                self.passed += 1;
                println!("  [ok]   {name}");
            }
            Err(msg) => {
                self.failed += 1;
                println!("  [FALHA] {name}: {msg}");
            }
        }
    }
}

fn check(cond: bool, msg: impl Into<String>) -> Result<(), String> {
    if cond { Ok(()) } else { Err(msg.into()) }
}

fn expect_broker_err<T>(res: Result<T, BrokerError>) -> Result<BrokerError, String> {
    match res {
        Ok(_) => Err("A chamada deveria ter falhado.".to_owned()),
        Err(err) => Ok(err),
    }
}

fn expect_store_err<T>(res: Result<T, VaultError>, expected_code: &str) -> Result<(), String> {
    match res {
        Ok(_) => Err(format!("esperava erro {expected_code}, mas teve sucesso")),
        Err(err) if err.code() == Some(expected_code) => Ok(()),
        Err(err) => Err(format!("esperava erro {expected_code}, veio {err:?}")),
    }
}

fn contains_secret<T: serde::Serialize>(payload: &T) -> bool {
    let rendered = serde_json::to_string(payload).unwrap_or_default();
    rendered.contains(SENHA_FAKE) || rendered.contains(CPF_FAKE)
}

fn try_delete_dir(dir: &Path) {
    let _ = fs::remove_dir_all(dir);
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("uso: svault-smoke <caminho-do-svault-broker.exe> [caminho-do-svault-mcp.exe]");
        return ExitCode::from(1);
    }

    let broker_exe = PathBuf::from(&args[0]);
    if !broker_exe.exists() {
        eprintln!("broker nao encontrado: {}", broker_exe.display());
        return ExitCode::from(1);
    }

    let mcp_exe = args
        .get(1)
        .map(PathBuf::from)
        .or_else(|| broker_exe.parent().map(|p| p.join("svault-mcp.exe")))
        .filter(|p| p.exists());

    let mut runner = Runner::new();
    run_vault_store_regressions(&mut runner).await;

    let home = env::temp_dir().join(format!("svault-smoke-{}", VaultCrypto::random_id()));
    let pipe_name = format!("svault.smoke.{}", &VaultCrypto::random_id()[..8]);
    fs::create_dir_all(&home).unwrap();

    let server = FakeHttpServer::start();
    let mut broker_child = start_broker(&broker_exe, &home, &pipe_name);
    let client = BrokerClient::new(&pipe_name);

    let pipe_ready = wait_for_pipe(&client);
    if let Err(err) = pipe_ready {
        println!("  [FALHA] inicializacao do pipe: {err}");
        runner.failed += 1;
    } else {
        run_live_broker_tests(&mut runner, &client, &server, &home).await;
        if let Some(mcp_bin) = &mcp_exe {
            run_mcp_tests(&mut runner, mcp_bin, &pipe_name);
        }
    }

    let _ = broker_child.kill();
    let _ = broker_child.wait();
    try_delete_dir(&home);

    println!();
    println!(
        "resultado: {} aprovado(s), {} falha(s)",
        runner.passed, runner.failed
    );
    if runner.failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn start_broker(exe: &Path, home: &Path, pipe_name: &str) -> Child {
    Command::new(exe)
        .args([
            "--console",
            "--in-memory-credentials",
            "--home",
            &home.to_string_lossy(),
            "--pipe",
            pipe_name,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("falha ao iniciar svault-broker")
}

fn wait_for_pipe(client: &BrokerClient) -> Result<(), String> {
    let mut last = String::new();
    for _ in 0..60 {
        match client.health() {
            Ok(_) => return Ok(()),
            Err(e) => {
                last = e.message;
                thread::sleep(Duration::from_millis(250));
            }
        }
    }
    Err(format!("O broker nao respondeu no pipe: {last}"))
}

async fn run_vault_store_regressions(runner: &mut Runner) {
    runner.test(
        "redacao cobre segredos curtos e JSON escapado sem alterar a mascara",
        || {
            let redactor = SecretRedactor::from_single(b"fake&value");
            let json = redactor.redact("{\"echo\":\"fake\\u0026value\"}");
            check(
                !json.contains("fake"),
                "o segredo JSON escapado permaneceu visivel",
            )?;

            let short_redactor = SecretRedactor::from_single(b"R");
            let once = short_redactor.redact("secret=R");
            check(
                once == short_redactor.redact(&once),
                "a segunda redacao alterou o marcador",
            )?;

            let marker_secret = SecretRedactor::from_single(b"***REDACTED***suffix-privado");
            check(
                !marker_secret
                    .redact("prefix=***REDACTED***suffix-privado")
                    .contains("suffix-privado"),
                "segredo que comeca pelo marcador permaneceu visivel",
            )?;

            let boolean_secret = SecretRedactor::from_single(b"false");
            check(
                boolean_secret.redact("{\"value\":false}").contains(MASK),
                "valor booleano igual ao segredo nao foi redigido",
            )?;
            Ok(())
        },
    );

    runner.test("alteracoes administrativas exigem o TOTP atual", || {
        let folder = env::temp_dir().join(format!("svault-totp-{}", VaultCrypto::random_id()));
        fs::create_dir_all(&folder).unwrap();
        let res = (|| -> Result<(), String> {
            let store = VaultStore::new(
                Some(folder.join("state.json")),
                Some(Arc::new(MemoryCredentialStore::new())),
            )
            .unwrap();
            let passphrase = "senha-totp-de-teste";
            let secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
            store.initialize(passphrase, true, Some(secret)).unwrap();
            let new_secret = "KRUGS4ZANFZSAYJAKRUGS4ZANFZSAYJA";

            expect_store_err(store.set_totp(new_secret, passphrase, None), "totp_invalid")?;
            expect_store_err(store.disable_totp(passphrase, None), "totp_invalid")?;
            expect_store_err(
                store.change_passphrase(passphrase, "nova-senha-totp", None),
                "totp_invalid",
            )?;
            expect_store_err(store.reset(passphrase, None), "totp_invalid")?;
            check(
                store.totp_enabled() && store.verify_passphrase(passphrase).unwrap(),
                "uma administracao sem TOTP alterou o cofre",
            )?;

            let code = Totp::generate_code(secret, Utc::now())?;
            store
                .set_totp(new_secret, passphrase, Some(&code))
                .map_err(|e| e.to_string())?;
            check(
                store.totp_enabled(),
                "TOTP valido nao permitiu a troca do fator",
            )?;

            let new_code = Totp::generate_code(new_secret, Utc::now())?;
            store
                .disable_totp(passphrase, Some(&new_code))
                .map_err(|e| e.to_string())?;
            check(
                !store.totp_enabled(),
                "TOTP valido nao permitiu a desativacao",
            )?;
            Ok(())
        })();
        try_delete_dir(&folder);
        res
    });

    runner.test(
        "politica de URL distingue caminho e normaliza apenas esquema e host",
        || {
            let allowed = vec!["https://example.com/Admin".to_owned()];
            check(
                !TargetPolicy::is_target_allowed(&allowed, "https://example.com/admin"),
                "caminhos diferiram apenas por caixa e foram aceitos",
            )?;
            check(
                TargetPolicy::is_target_allowed(&allowed, "HTTPS://EXAMPLE.COM/Admin?x=1"),
                "host ou query permitida foi recusada",
            )?;
            check(
                !TargetPolicy::is_target_allowed(&allowed, "https://user@example.com/Admin"),
                "userinfo foi aceito",
            )?;
            check(
                !TargetPolicy::is_target_allowed(&allowed, "https://example.com/Admin#frag"),
                "fragmento foi aceito",
            )?;
            Ok(())
        },
    );

    runner.test(
        "interpolacao trata delimitadores em segredos e parametros como dados",
        || {
            let secret = b"valor{{injetado}}".to_vec();
            let mut parameters = BTreeMap::new();
            parameters.insert("p".to_owned(), "param{{injetado}}".to_owned());

            let mut body_fields = BTreeMap::new();
            body_fields.insert("value".to_owned(), "{{secret}}/{{param:p}}".to_owned());

            let context = OperationContext {
                operation: OperationRecord {
                    action: OperationEngine::ACTION_HTTP_REQUEST.to_owned(),
                    params: vec!["p".to_owned()],
                    http: Some(HttpRequestRecord {
                        body_fields,
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                secret: Zeroizing::new(secret.clone()),
                referenced_secrets: HashMap::new(),
                parameters,
                redactor: SecretRedactor::from_single(&secret),
            };

            let result = OperationEngine::resolve_template("{{secret}}/{{param:p}}", &context)
                .map_err(|e| e.message)?;
            check(
                result == "valor{{injetado}}/param{{injetado}}",
                "valores com chaves foram reinterpretados ou recusados",
            )?;

            let composed = OperationEngine::resolve_template("inicio-{{secret}}-fim", &context)
                .map_err(|e| e.message)?;
            check(
                composed == "inicio-valor{{injetado}}-fim",
                "interpolacao composta alterou o segredo",
            )?;

            check(
                OperationEngine::resolve_template("{{placeholder-invalido}}", &context).is_err(),
                "template original invalido foi aceito",
            )?;
            Ok(())
        },
    );

    let proc_res = {
        let context = OperationContext {
            operation: OperationRecord {
                action: OperationEngine::ACTION_PROCESS_STDIN.to_owned(),
                process: Some(ProcessRecord {
                    executable: "executavel-inexistente".to_owned(),
                    ..Default::default()
                }),
                ..Default::default()
            },
            secret: Zeroizing::new(Vec::new()),
            referenced_secrets: HashMap::new(),
            parameters: BTreeMap::new(),
            redactor: SecretRedactor::new(std::iter::empty()),
        };
        OperationEngine::execute_async(&context).await
    };
    runner.test(
        "process.stdin legado e recusado sem iniciar executavel",
        move || {
            check(proc_res.is_err(), "process.stdin legado foi executado")
        },
    );

    runner.test("rotacao falha sem danificar geracao anterior", || {
        let folder = env::temp_dir().join(format!("svault-rotation-{}", VaultCrypto::random_id()));
        fs::create_dir_all(&folder).unwrap();
        let res = (|| -> Result<(), String> {
            let state_file = folder.join("state.json");
            let storage = Arc::new(FailingCredentialStore::new());
            let store =
                VaultStore::new(Some(state_file.clone()), Some(storage.clone())).unwrap();
            store
                .initialize("senha-antiga-de-teste", false, None)
                .unwrap();
            store
                .register_entry(
                    "A",
                    "generic",
                    "A",
                    &[],
                    b"segredo-a",
                    "senha-antiga-de-teste",
                )
                .unwrap();
            store
                .register_entry(
                    "B",
                    "generic",
                    "B",
                    &[],
                    b"segredo-b",
                    "senha-antiga-de-teste",
                )
                .unwrap();

            storage.fail_on_write(Some(2));
            check(
                store
                    .change_passphrase("senha-antiga-de-teste", "senha-nova-de-teste", None)
                    .is_err(),
                "a falha de escrita deveria interromper a rotacao",
            )?;

            storage.fail_on_write(None);
            let reopened =
                VaultStore::new(Some(state_file.clone()), Some(storage.clone())).unwrap();
            check(
                reopened
                    .verify_passphrase("senha-antiga-de-teste")
                    .unwrap(),
                "a senha antiga deixou de abrir o cofre",
            )?;
            check(
                !reopened.verify_passphrase("senha-nova-de-teste").unwrap(),
                "a senha nova foi confirmada sem commit",
            )?;
            check(
                &reopened
                    .unwrap_secret("A", "senha-antiga-de-teste")
                    .unwrap()[..]
                    == b"segredo-a",
                "o primeiro segredo foi alterado",
            )?;
            check(
                &reopened
                    .unwrap_secret("B", "senha-antiga-de-teste")
                    .unwrap()[..]
                    == b"segredo-b",
                "o segundo segredo foi alterado",
            )?;

            storage.fail_on_read(Some(1));
            check(
                reopened
                    .change_passphrase("senha-antiga-de-teste", "senha-nova-de-teste", None)
                    .is_err(),
                "a falha de leitura deveria interromper a rotacao",
            )?;
            storage.fail_on_read(None);

            let reopened =
                VaultStore::new(Some(state_file.clone()), Some(storage.clone())).unwrap();
            check(
                reopened
                    .verify_passphrase("senha-antiga-de-teste")
                    .unwrap(),
                "a falha de leitura invalidou a senha antiga",
            )?;

            let lock_holder: Arc<Mutex<Option<File>>> = Arc::new(Mutex::new(None));
            let lock_clone = Arc::clone(&lock_holder);
            let sf_clone = state_file.clone();
            storage.fail_on_write(None);
            storage.set_after_write(Some(Box::new(move |number| {
                if number == 2 {
                    let mut opts = OpenOptions::new();
                    opts.read(true);
                    #[cfg(windows)]
                    {
                        use std::os::windows::fs::OpenOptionsExt;
                        // FILE_SHARE_READ = 1 (no FILE_SHARE_DELETE)
                        opts.share_mode(1);
                    }
                    if let Ok(f) = opts.open(&sf_clone) {
                        *lock_clone.lock().unwrap() = Some(f);
                    }
                }
            })));

            let commit_blocked = reopened.change_passphrase(
                "senha-antiga-de-teste",
                "senha-nova-de-teste",
                None,
            );
            *lock_holder.lock().unwrap() = None;
            storage.set_after_write(None);
            check(
                commit_blocked.is_err(),
                "o bloqueio do commit deveria interromper a rotacao",
            )?;

            let reopened =
                VaultStore::new(Some(state_file.clone()), Some(storage.clone())).unwrap();
            check(
                reopened
                    .verify_passphrase("senha-antiga-de-teste")
                    .unwrap(),
                "a falha no commit invalidou a senha antiga",
            )?;
            check(
                &reopened
                    .unwrap_secret("B", "senha-antiga-de-teste")
                    .unwrap()[..]
                    == b"segredo-b",
                "a falha no commit alterou o segundo segredo",
            )?;

            reopened
                .change_passphrase("senha-antiga-de-teste", "senha-nova-de-teste", None)
                .map_err(|e| e.to_string())?;
            let after_commit =
                VaultStore::new(Some(state_file.clone()), Some(storage.clone())).unwrap();
            check(
                !after_commit
                    .verify_passphrase("senha-antiga-de-teste")
                    .unwrap(),
                "a senha antiga permaneceu ativa apos commit",
            )?;
            check(
                after_commit
                    .verify_passphrase("senha-nova-de-teste")
                    .unwrap(),
                "a senha nova nao abriu apos commit",
            )?;
            check(
                &after_commit
                    .unwrap_secret("B", "senha-nova-de-teste")
                    .unwrap()[..]
                    == b"segredo-b",
                "segredo ausente apos commit",
            )?;

            expect_store_err(
                after_commit.change_passphrase("senha-nova-de-teste", "curta", None),
                "bad_request",
            )?;
            check(
                after_commit
                    .verify_passphrase("senha-nova-de-teste")
                    .unwrap(),
                "senha curta alterou o estado persistido",
            )?;

            storage
                .write("SVault:entry:sentinela", "teste", b"nao-remover")
                .unwrap();
            after_commit.reset("senha-nova-de-teste", None).unwrap();
            check(
                storage.list_targets("SVault:entry").unwrap()
                    == vec!["SVault:entry:sentinela".to_owned()],
                "reset removeu alvo de terceiro ou manteve alvo inventariado",
            )?;
            Ok(())
        })();
        try_delete_dir(&folder);
        res
    });

    runner.test(
        "rotacao preserva TOTP e carrega estado legado sem geracao",
        || {
            let folder = env::temp_dir().join(format!(
                "svault-legacy-rotation-{}",
                VaultCrypto::random_id()
            ));
            fs::create_dir_all(&folder).unwrap();
            let res = (|| -> Result<(), String> {
                let state_file = folder.join("state.json");
                let credentials = Arc::new(MemoryCredentialStore::new());
                let store =
                    VaultStore::new(Some(state_file.clone()), Some(credentials.clone())).unwrap();
                let old_passphrase = "senha-legada-de-teste";
                let totp_secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
                store
                    .initialize(old_passphrase, true, Some(totp_secret))
                    .unwrap();
                store
                    .register_entry(
                        "A",
                        "generic",
                        "A",
                        &[],
                        b"segredo-legado",
                        old_passphrase,
                    )
                    .unwrap();

                let mut legacy_state: VaultState =
                    serde_json::from_str(&fs::read_to_string(&state_file).unwrap()).unwrap();
                check(
                    legacy_state.entries.len() == 1,
                    "fixture nao persistiu um registro",
                )?;
                let entry_id = legacy_state.entries[0].id.clone();
                let current_target = legacy_state
                    .known_credential_targets
                    .iter()
                    .find(|t| t.ends_with(&format!(":{entry_id}")))
                    .cloned()
                    .unwrap();
                let blob = credentials.read(&current_target).unwrap().unwrap();
                credentials
                    .write("SVault:entry:A", &entry_id, &blob)
                    .unwrap();
                legacy_state.credential_generation = None;
                legacy_state.entries[0].credential_version = None;
                fs::write(
                    &state_file,
                    serde_json::to_string(&legacy_state).unwrap(),
                )
                .unwrap();

                let reopened_legacy =
                    VaultStore::new(Some(state_file.clone()), Some(credentials.clone())).unwrap();
                check(
                    reopened_legacy.verify_passphrase(old_passphrase).unwrap(),
                    "estado legado sem geracao nao abriu",
                )?;
                check(
                    &reopened_legacy.unwrap_secret("A", old_passphrase).unwrap()[..]
                        == b"segredo-legado",
                    "alvo de credencial legado nao foi carregado",
                )?;

                let old_code = Totp::generate_code(totp_secret, Utc::now())?;
                reopened_legacy
                    .change_passphrase(old_passphrase, "senha-nova-legada", Some(&old_code))
                    .map_err(|e| e.to_string())?;

                let reopened_rotated =
                    VaultStore::new(Some(state_file.clone()), Some(credentials.clone())).unwrap();
                check(
                    reopened_rotated
                        .verify_passphrase("senha-nova-legada")
                        .unwrap(),
                    "rotacao de estado legado nao persistiu a senha nova",
                )?;
                check(reopened_rotated.totp_enabled(), "rotacao desativou o TOTP")?;

                let new_code = Totp::generate_code(totp_secret, Utc::now())?;
                reopened_rotated
                    .change_passphrase("senha-nova-legada", "terceira-senha-legada", Some(&new_code))
                    .map_err(|e| e.to_string())?;
                check(
                    reopened_rotated
                        .verify_passphrase("terceira-senha-legada")
                        .unwrap(),
                    "TOTP preservado nao autorizou nova rotacao",
                )?;
                check(
                    reopened_rotated.totp_enabled(),
                    "a segunda rotacao desativou o TOTP",
                )?;
                check(
                    &reopened_rotated
                        .unwrap_secret("A", "terceira-senha-legada")
                        .unwrap()[..]
                        == b"segredo-legado",
                    "rotacao de estado legado perdeu o segredo",
                )?;
                Ok(())
            })();
            try_delete_dir(&folder);
            res
        },
    );
}

async fn run_live_broker_tests(
    runner: &mut Runner,
    client: &BrokerClient,
    server: &FakeHttpServer,
    home: &Path,
) {
    let mut totp_secret_holder: Option<String> = None;

    runner.test("broker responde ao health", || {
        let health = client.health().map_err(|e| e.to_string())?;
        check(health.status == "ok", "status diferente de ok")?;
        check(
            !health.vault_initialized,
            "o cofre deveria comecar nao inicializado",
        )
    });

    runner.test(
        "cofre nao inicializado bloqueia leitura de segredos",
        || {
            let err = expect_broker_err(
                client.send_raw("get_secret", Some(&json!({ "id": "CPF_PESSOAL" }))),
            )?;
            check(
                err.code == "bad_request",
                format!("codigo inesperado: {}", err.code),
            )
        },
    );

    runner.test("inicializa o cofre", || {
        client
            .init_vault(PASSPHRASE, false)
            .map_err(|e| e.to_string())?;
        let health = client.health().map_err(|e| e.to_string())?;
        check(health.vault_initialized, "o cofre nao ficou inicializado")
    });

    runner.test("senha do cofre errada e rejeitada", || {
        let err = expect_broker_err(client.init_vault("outra-senha", false))?;
        check(
            err.code == "conflict",
            format!("codigo inesperado: {}", err.code),
        )
    });

    runner.test("cadastra segredos ficticios", || {
        let targets = vec![server.base_url()];
        client
            .register_entry(
                "CPF_PESSOAL",
                "cpf",
                "CPF pessoal (ficticio)",
                &targets,
                CPF_FAKE,
                PASSPHRASE,
            )
            .map_err(|e| e.to_string())?;
        client
            .register_entry(
                "SENHA_PORTAL_A",
                "password",
                "Senha do portal A (ficticia)",
                &targets,
                SENHA_FAKE,
                PASSPHRASE,
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    });

    runner.test("senha do cofre errada nao altera segredos", || {
        let targets = vec![server.base_url()];
        let err = expect_broker_err(client.register_entry(
            "X",
            "generic",
            "X",
            &targets,
            "valor",
            "senha-errada",
        ))?;
        check(
            err.code == "passphrase_invalid",
            format!("codigo inesperado: {}", err.code),
        )
    });

    runner.test("listagem de registros expoe apenas metadados", || {
        let entries = client.list_entries().map_err(|e| e.to_string())?;
        check(
            entries.len() == 2,
            format!("esperava 2 registros, veio {}", entries.len()),
        )?;
        check(
            entries.iter().any(|e| e.id == "CPF_PESSOAL"),
            "CPF_PESSOAL ausente",
        )?;
        check(
            !contains_secret(&entries),
            "a listagem vazou um valor de segredo",
        )
    });

    runner.test("autoriza operacoes com alvo e acao fixos", || {
        let login_url = format!("{}/api/login", server.base_url());
        let mut login_body = BTreeMap::new();
        login_body.insert(
            "usuario".to_owned(),
            "Bearer {{param:usuario}} {{secret}}".to_owned(),
        );
        login_body.insert("senha".to_owned(), "{{secret}}".to_owned());

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
                        body_fields: login_body,
                        headers: BTreeMap::new(),
                        result_fields: Vec::new(),
                    }),
                    process: None,
                },
                PASSPHRASE,
            )
            .map_err(|e| e.to_string())?;

        let cpf_url = format!("{}/api/cpf", server.base_url());
        let mut cpf_body = BTreeMap::new();
        cpf_body.insert("cpf".into(), "{{secret}}".into());
        client
            .authorize_operation(
                &AuthorizeRequest {
                    id: "enviar_cpf".into(),
                    entry_id: "CPF_PESSOAL".into(),
                    action: "http.request".into(),
                    target: cpf_url.clone(),
                    description: "Envio ficticio de CPF".into(),
                    params: Vec::new(),
                    http: Some(HttpSpec {
                        method: "POST".into(),
                        url: cpf_url,
                        content_type: "application/json".into(),
                        body_fields: cpf_body.clone(),
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
                    id: "eco_teste".into(),
                    entry_id: "CPF_PESSOAL".into(),
                    action: "noop.echo".into(),
                    target: "eco".into(),
                    description: "Teste de redacao sem rede".into(),
                    params: Vec::new(),
                    http: None,
                    process: None,
                },
                PASSPHRASE,
            )
            .map_err(|e| e.to_string())?;

        let invalid_url = format!("{}/invalid-json", server.base_url());
        client
            .authorize_operation(
                &AuthorizeRequest {
                    id: "json_invalido".into(),
                    entry_id: "CPF_PESSOAL".into(),
                    action: "http.request".into(),
                    target: invalid_url.clone(),
                    description: "Teste de selecao restritiva".into(),
                    params: Vec::new(),
                    http: Some(HttpSpec {
                        method: "POST".into(),
                        url: invalid_url,
                        content_type: "application/json".into(),
                        body_fields: cpf_body,
                        headers: BTreeMap::new(),
                        result_fields: vec!["safe".into()],
                    }),
                    process: None,
                },
                PASSPHRASE,
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    });

    runner.test("alvo nao autorizado para o registro e recusado", || {
        let mut body = BTreeMap::new();
        body.insert("cpf".into(), "{{secret}}".into());
        let bad_url = "https://site-nao-autorizado.exemplo.com/login".to_owned();
        let err = expect_broker_err(client.authorize_operation(
            &AuthorizeRequest {
                id: "op_indevida".into(),
                entry_id: "CPF_PESSOAL".into(),
                action: "http.request".into(),
                target: bad_url.clone(),
                description: "alvo indevido".into(),
                params: Vec::new(),
                http: Some(HttpSpec {
                    method: "POST".into(),
                    url: bad_url,
                    content_type: "application/json".into(),
                    body_fields: body,
                    headers: BTreeMap::new(),
                    result_fields: Vec::new(),
                }),
                process: None,
            },
            PASSPHRASE,
        ))?;
        check(
            err.code == "target_not_allowed",
            format!("codigo inesperado: {}", err.code),
        )
    });

    runner.test("segredo literal no template e recusado", || {
        let mut body = BTreeMap::new();
        body.insert("senha".into(), SENHA_FAKE.into());
        let url = format!("{}/api/literal", server.base_url());
        let err = expect_broker_err(client.authorize_operation(
            &AuthorizeRequest {
                id: "op_literal".into(),
                entry_id: "SENHA_PORTAL_A".into(),
                action: "http.request".into(),
                target: url.clone(),
                description: "template com segredo literal".into(),
                params: Vec::new(),
                http: Some(HttpSpec {
                    method: "POST".into(),
                    url,
                    content_type: "application/json".into(),
                    body_fields: body,
                    headers: BTreeMap::new(),
                    result_fields: Vec::new(),
                }),
                process: None,
            },
            PASSPHRASE,
        ))?;
        check(
            err.code == "bad_request",
            format!("codigo inesperado: {}", err.code),
        )
    });

    runner.test(
        "segredos de um a tres caracteres nao podem ser persistidos em templates",
        || {
            let targets = vec![server.base_url()];
            client
                .register_entry(
                    "SEGREDO_CURTO",
                    "generic",
                    "segredo curto sintetico",
                    &targets,
                    "a",
                    PASSPHRASE,
                )
                .map_err(|e| e.to_string())?;

            let res = (|| -> Result<(), String> {
                let cases = ["a", "bc", "xyz", " "];
                for (idx, secret) in cases.iter().enumerate() {
                    client
                        .update_entry("SEGREDO_CURTO", Some(secret), None, None, PASSPHRASE)
                        .map_err(|e| e.to_string())?;
                    let mut body = BTreeMap::new();
                    body.insert(
                        "value".into(),
                        format!("literal-prefix-{secret}-suffix"),
                    );
                    let url = format!("{}/curto/{idx}", server.base_url());
                    let err = expect_broker_err(client.authorize_operation(
                        &AuthorizeRequest {
                            id: format!("curto_literal_{idx}"),
                            entry_id: "SEGREDO_CURTO".into(),
                            action: "http.request".into(),
                            target: url.clone(),
                            description: "validacao de segredo literal curto".into(),
                            params: Vec::new(),
                            http: Some(HttpSpec {
                                method: "POST".into(),
                                url,
                                content_type: "application/json".into(),
                                body_fields: body,
                                headers: BTreeMap::new(),
                                result_fields: Vec::new(),
                            }),
                            process: None,
                        },
                        PASSPHRASE,
                    ))?;
                    check(
                        err.code == "bad_request",
                        format!("literal de {} caractere(s) foi aceito", secret.len()),
                    )?;

                    if idx == 2 {
                        let mut adj_body = BTreeMap::new();
                        adj_body.insert("value".into(), "{{secret}}xyz{{param:p}}".into());
                        let adj_url = format!("{}/curto/placeholder", server.base_url());
                        let adj_err = expect_broker_err(client.authorize_operation(
                            &AuthorizeRequest {
                                id: "curto_placeholder_adjacente".into(),
                                entry_id: "SEGREDO_CURTO".into(),
                                action: "http.request".into(),
                                target: adj_url.clone(),
                                description: "literal entre placeholders".into(),
                                params: vec!["p".into()],
                                http: Some(HttpSpec {
                                    method: "POST".into(),
                                    url: adj_url,
                                    content_type: "application/json".into(),
                                    body_fields: adj_body,
                                    headers: BTreeMap::new(),
                                    result_fields: Vec::new(),
                                }),
                                process: None,
                            },
                            PASSPHRASE,
                        ))?;
                        check(
                            adj_err.code == "bad_request",
                            "segredo curto adjacente a placeholders foi aceito",
                        )?;
                    }
                }

                let persisted = fs::read_to_string(home.join("state").join("vault-state.json"))
                    .map_err(|e| e.to_string())?;
                check(
                    !persisted.contains("literal-prefix-xyz-suffix"),
                    "literal curto apareceu no arquivo de estado",
                )?;
                let ops = client.list_operations().map_err(|e| e.to_string())?;
                check(
                    !ops.iter().any(|o| o.id.starts_with("curto_literal_")),
                    "autorizacao recusada foi persistida",
                )
            })();

            let _ = client.delete_entry("SEGREDO_CURTO", PASSPHRASE);
            res
        },
    );

    runner.test(
        "templates invalidos sao recusados antes de persistir autorizacao",
        || {
            let mut body = BTreeMap::new();
            body.insert("value".into(), "{{param:ausente}}".into());
            let url = format!("{}/template-invalido", server.base_url());
            let err = expect_broker_err(client.authorize_operation(
                &AuthorizeRequest {
                    id: "template_parametro_nao_declarado".into(),
                    entry_id: "CPF_PESSOAL".into(),
                    action: "http.request".into(),
                    target: url.clone(),
                    description: "template com parametro nao declarado".into(),
                    params: Vec::new(),
                    http: Some(HttpSpec {
                        method: "POST".into(),
                        url,
                        content_type: "application/json".into(),
                        body_fields: body,
                        headers: BTreeMap::new(),
                        result_fields: Vec::new(),
                    }),
                    process: None,
                },
                PASSPHRASE,
            ))?;
            check(
                err.code == "bad_request",
                format!("template invalido retornou {}", err.code),
            )?;
            let ops = client.list_operations().map_err(|e| e.to_string())?;
            check(
                !ops.iter()
                    .any(|o| o.id == "template_parametro_nao_declarado"),
                "template invalido foi persistido",
            )
        },
    );

    let legacy_url_check = {
        let folder = env::temp_dir().join(format!("svault-legacy-url-{}", VaultCrypto::random_id()));
        fs::create_dir_all(&folder).unwrap();
        let res = async {
            let credentials = Arc::new(CountingCredentialStore::new());
            let store = Arc::new(
                VaultStore::new(
                    Some(folder.join("state.json")),
                    Some(credentials.clone()),
                )
                .unwrap(),
            );
            let passphrase = "senha-legada-url";
            store.initialize(passphrase, false, None).unwrap();
            let target = format!("{}/Admin", server.base_url());
            store
                .register_entry(
                    "LEGACY_URL",
                    "generic",
                    "destino legado",
                    std::slice::from_ref(&target),
                    b"segredo-sintetico",
                    passphrase,
                )
                .unwrap();
            store
                .authorize_operation(
                    OperationRecord {
                        id: "http_legado".into(),
                        entry_id: "LEGACY_URL".into(),
                        action: "http.request".into(),
                        target: target.clone(),
                        http: Some(HttpRequestRecord {
                            method: "GET".into(),
                            url: format!("{}/admin", server.base_url()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    passphrase,
                )
                .unwrap();

            let engine = BrokerEngine::new(
                store,
                Arc::new(VaultLog::new(Some(&folder.join("broker.log")))),
                BrokerConfig::default(),
            );
            let req_resp = engine
                .handle_async(
                    Envelope {
                        cmd: "request_operation".into(),
                        body: Some(json!({ "opId": "http_legado", "params": {} })),
                    },
                    "sintetico",
                )
                .await;
            check(
                req_resp.ok && req_resp.data.is_some(),
                "a solicitacao legada de teste nao foi criada",
            )?;
            let req: OperationRequestResult =
                serde_json::from_value(req_resp.data.unwrap()).unwrap();
            credentials.reset_read_count();
            let before = server.bodies().len();

            let approval = engine
                .handle_async(
                    Envelope {
                        cmd: "approve".into(),
                        body: Some(json!({ "requestId": req.request_id, "passphrase": passphrase })),
                    },
                    "sintetico",
                )
                .await;
            let after = server.bodies().len();
            check(
                !approval.ok
                    && approval.error.as_ref().map(|e| e.code.as_str())
                        == Some("target_not_allowed"),
                "URL legada divergente nao foi recusada",
            )?;
            check(
                credentials.read_count() == 0,
                "segredo foi aberto antes de validar a URL efetiva",
            )?;
            check(
                after == before,
                "pedido chegou ao destino fora do alvo autorizado",
            )
        }
        .await;
        try_delete_dir(&folder);
        res
    };
    runner.test(
        "URL efetiva de autorizacao legada e revalidada antes de abrir segredos",
        move || legacy_url_check,
    );

    runner.test("solicitacao do agente nao devolve segredo", || {
        let mut params = BTreeMap::new();
        params.insert("usuario".into(), "usuario-ficticio".into());
        let request = client
            .request_operation("login_portal_a", Some(&params))
            .map_err(|e| e.to_string())?;
        check(
            request.status == "pending_approval",
            format!("status inesperado: {}", request.status),
        )?;
        check(
            request.requires == "passphrase",
            format!("requisicao inesperada: {}", request.requires),
        )?;
        check(
            request.summary.parameters.get("usuario").map(String::as_str)
                == Some("usuario-ficticio"),
            "parametro efetivo ausente do resumo",
        )?;
        check(!contains_secret(&request), "a solicitacao vazou o segredo")
    });

    runner.test(
        "parametro obrigatorio ausente e recusado antes de criar solicitacao",
        || {
            let err = expect_broker_err(client.request_operation("login_portal_a", None))?;
            check(
                err.code == "bad_request",
                format!("codigo inesperado: {}", err.code),
            )?;
            let type_err = expect_broker_err(client.send_raw(
                "request_operation",
                Some(&json!({ "opId": "login_portal_a", "params": { "usuario": 7 } })),
            ))?;
            check(
                type_err.code == "bad_request",
                format!("tipo de parametro inesperado aceito: {}", type_err.code),
            )
        },
    );

    runner.test("JSON invalido nunca retorna corpo fora da selecao", || {
        let request = client
            .request_operation("json_invalido", None)
            .map_err(|e| e.to_string())?;
        let result = client
            .approve(&request.request_id, PASSPHRASE, None)
            .map_err(|e| e.to_string())?;
        let rendered = serde_json::to_string(&result).unwrap();
        check(
            result.status.as_deref() == Some("failed"),
            format!("status inesperado: {:?}", result.status),
        )?;
        check(
            !rendered.contains("raw-invalid-secret"),
            "corpo JSON invalido foi devolvido",
        )?;
        check(
            result.error.as_deref() == Some("Falha na execucao autorizada."),
            "erro de execucao expos detalhe externo",
        )
    });

    runner.test("aprovacao com senha errada falha", || {
        let mut params = BTreeMap::new();
        params.insert("usuario".into(), "usuario-ficticio".into());
        let request = client
            .request_operation("login_portal_a", Some(&params))
            .map_err(|e| e.to_string())?;
        let err = expect_broker_err(client.approve(&request.request_id, "senha-errada", None))?;
        check(
            err.code == "passphrase_invalid",
            format!("codigo inesperado: {}", err.code),
        )
    });

    runner.test("aprovacao executa e devolve resultado sanitizado", || {
        let mut params = BTreeMap::new();
        params.insert("usuario".into(), "usuario-ficticio".into());
        let request = client
            .request_operation("login_portal_a", Some(&params))
            .map_err(|e| e.to_string())?;
        let approval = client
            .approve(&request.request_id, PASSPHRASE, None)
            .map_err(|e| e.to_string())?;
        check(
            approval.status.as_deref() == Some("completed"),
            format!("status inesperado: {:?}", approval.status),
        )?;

        let rendered = serde_json::to_string(&approval).unwrap();
        check(
            rendered.contains("***REDACTED***"),
            "o resultado nao foi redigido",
        )?;
        check(!rendered.contains(SENHA_FAKE), "a senha vazou no resultado")?;
        check(!rendered.contains(CPF_FAKE), "o cpf vazou no resultado")?;

        let bodies = server.bodies();
        check(!bodies.is_empty(), "o servidor fake nao recebeu a requisicao")?;
        let last = bodies.last().unwrap();
        check(
            last.contains(SENHA_FAKE),
            "o broker nao enviou o segredo ao destino autorizado",
        )?;
        check(
            last.contains("Bearer usuario-ficticio"),
            "template composto nao resolveu o parametro junto com texto literal",
        )
    });

    runner.test("resultado por status permanece sanitizado", || {
        let request = client
            .request_operation("enviar_cpf", None)
            .map_err(|e| e.to_string())?;
        client
            .approve(&request.request_id, PASSPHRASE, None)
            .map_err(|e| e.to_string())?;
        let status = client
            .operation_status(&request.request_id)
            .map_err(|e| e.to_string())?;
        let rendered = serde_json::to_string(&status).unwrap();
        check(
            status.status == "completed",
            format!("status inesperado: {}", status.status),
        )?;
        check(!rendered.contains(CPF_FAKE), "o cpf vazou no status")
    });

    runner.test("aprovacao concorrente executa uma unica requisicao", || {
        let mut params = BTreeMap::new();
        params.insert("usuario".into(), "concorrente".into());
        let request = client
            .request_operation("login_portal_a", Some(&params))
            .map_err(|e| e.to_string())?;
        let before = server.bodies().len();

        let c1 = client.clone();
        let id1 = request.request_id.clone();
        let t1 = thread::spawn(move || match c1.approve(&id1, PASSPHRASE, None) {
            Ok(r) => r.status.unwrap_or_default(),
            Err(e) => e.code,
        });

        let c2 = client.clone();
        let id2 = request.request_id.clone();
        let t2 = thread::spawn(move || match c2.approve(&id2, PASSPHRASE, None) {
            Ok(r) => r.status.unwrap_or_default(),
            Err(e) => e.code,
        });

        let outcomes = [t1.join().unwrap(), t2.join().unwrap()];
        check(
            outcomes.iter().filter(|v| v.as_str() == "completed").count() == 1,
            format!("nao houve exatamente uma aprovacao concluida: {outcomes:?}"),
        )?;
        check(
            outcomes.iter().filter(|v| v.as_str() == "conflict").count() == 1,
            format!("a segunda aprovacao nao recebeu conflito: {outcomes:?}"),
        )?;
        check(
            server.bodies().len() == before + 1,
            "a requisicao foi enviada mais de uma vez",
        )?;
        let rejected = expect_broker_err(client.reject(&request.request_id, PASSPHRASE))?;
        check(
            rejected.code == "conflict",
            "rejeicao sobrescreveu uma operacao concluida",
        )
    });

    runner.test("acao noop eco devolve apenas mascara", || {
        let request = client
            .request_operation("eco_teste", None)
            .map_err(|e| e.to_string())?;
        let approval = client
            .approve(&request.request_id, PASSPHRASE, None)
            .map_err(|e| e.to_string())?;
        let rendered = serde_json::to_string(&approval.result).unwrap();
        check(rendered.contains("***REDACTED***"), "o eco nao foi redigido")?;
        check(!rendered.contains(CPF_FAKE), "o cpf vazou no eco")
    });

    runner.test(
        "revogar e reautorizar mesmo ID invalida pedido antigo",
        || {
            let request = client
                .request_operation("eco_teste", None)
                .map_err(|e| e.to_string())?;
            client
                .revoke_operation("eco_teste", PASSPHRASE)
                .map_err(|e| e.to_string())?;
            client
                .authorize_operation(
                    &AuthorizeRequest {
                        id: "eco_teste".into(),
                        entry_id: "CPF_PESSOAL".into(),
                        action: "noop.echo".into(),
                        target: "eco".into(),
                        description: "Teste de redacao sem rede".into(),
                        params: Vec::new(),
                        http: None,
                        process: None,
                    },
                    PASSPHRASE,
                )
                .map_err(|e| e.to_string())?;
            let err = expect_broker_err(client.approve(&request.request_id, PASSPHRASE, None))?;
            check(
                err.code == "conflict",
                format!("pedido revogado foi reutilizado: {}", err.code),
            )
        },
    );

    runner.test("mudanca de registro invalida pedido pendente", || {
        let mut params = BTreeMap::new();
        params.insert("usuario".into(), "alvo-alterado".into());
        let request = client
            .request_operation("login_portal_a", Some(&params))
            .map_err(|e| e.to_string())?;
        let previous = server.bodies().len();
        let changed = vec![format!("{}/changed", server.base_url())];
        client
            .update_entry("SENHA_PORTAL_A", None, None, Some(&changed), PASSPHRASE)
            .map_err(|e| e.to_string())?;
        let err = expect_broker_err(client.approve(&request.request_id, PASSPHRASE, None))?;
        check(
            err.code == "conflict",
            format!("pedido continuou valido apos revisao do registro: {}", err.code),
        )?;
        let restored = vec![server.base_url()];
        client
            .update_entry("SENHA_PORTAL_A", None, None, Some(&restored), PASSPHRASE)
            .map_err(|e| e.to_string())?;
        check(
            server.bodies().len() == previous,
            "pedido invalido alcancou o servidor",
        )
    });

    runner.test("operacao pode combinar dois registros autorizados", || {
        let targets = vec![server.base_url()];
        client
            .register_entry(
                "CPF_AUXILIAR",
                "generic",
                "Segundo registro (ficticio)",
                &targets,
                "AuxiliarFicticio!42",
                PASSPHRASE,
            )
            .map_err(|e| e.to_string())?;

        let url = format!("{}/api/login", server.base_url());
        let mut body = BTreeMap::new();
        body.insert("senha".into(), "{{secret}}".into());
        body.insert("auxiliar".into(), "{{secret:CPF_AUXILIAR}}".into());
        client
            .authorize_operation(
                &AuthorizeRequest {
                    id: "op_combinada".into(),
                    entry_id: "SENHA_PORTAL_A".into(),
                    action: "http.request".into(),
                    target: url.clone(),
                    description: "Usa dois registros na mesma requisicao".into(),
                    params: Vec::new(),
                    http: Some(HttpSpec {
                        method: "POST".into(),
                        url,
                        content_type: "application/json".into(),
                        body_fields: body,
                        headers: BTreeMap::new(),
                        result_fields: Vec::new(),
                    }),
                    process: None,
                },
                PASSPHRASE,
            )
            .map_err(|e| e.to_string())?;

        let request = client
            .request_operation("op_combinada", None)
            .map_err(|e| e.to_string())?;
        let approval = client
            .approve(&request.request_id, PASSPHRASE, None)
            .map_err(|e| e.to_string())?;
        check(
            approval.status.as_deref() == Some("completed"),
            format!("status inesperado: {:?}", approval.status),
        )?;
        let rendered = serde_json::to_string(&approval).unwrap();
        check(!rendered.contains(SENHA_FAKE), "a senha vazou no resultado")?;
        check(
            !rendered.contains("AuxiliarFicticio!42"),
            "o segredo auxiliar vazou",
        )?;

        let bodies = server.bodies();
        let last = bodies.last().unwrap();
        check(last.contains(SENHA_FAKE), "a senha nao chegou ao destino")?;
        check(
            last.contains("AuxiliarFicticio!42"),
            "o auxiliar nao chegou ao destino",
        )
    });

    runner.test(
        "referencia a registro sem permissao para o alvo e recusada",
        || {
            client
                .register_entry(
                    "OUTRO_ALVO",
                    "generic",
                    "Registro de outro alvo (ficticio)",
                    &["https://outro-site.exemplo.com".to_owned()],
                    "OutroValorFicticio",
                    PASSPHRASE,
                )
                .map_err(|e| e.to_string())?;

            let url = format!("{}/api/login", server.base_url());
            let mut body = BTreeMap::new();
            body.insert("senha".into(), "{{secret}}".into());
            body.insert("outro".into(), "{{secret:OUTRO_ALVO}}".into());
            let err = expect_broker_err(client.authorize_operation(
                &AuthorizeRequest {
                    id: "op_invalida".into(),
                    entry_id: "SENHA_PORTAL_A".into(),
                    action: "http.request".into(),
                    target: url.clone(),
                    description: "referencia indevida".into(),
                    params: Vec::new(),
                    http: Some(HttpSpec {
                        method: "POST".into(),
                        url,
                        content_type: "application/json".into(),
                        body_fields: body,
                        headers: BTreeMap::new(),
                        result_fields: Vec::new(),
                    }),
                    process: None,
                },
                PASSPHRASE,
            ))?;
            check(
                err.code == "target_not_allowed",
                format!("codigo inesperado: {}", err.code),
            )
        },
    );

    runner.test("agente nao consegue aprovar sem a senha do cofre", || {
        let mut params = BTreeMap::new();
        params.insert("usuario".into(), "usuario-ficticio".into());
        let request = client
            .request_operation("login_portal_a", Some(&params))
            .map_err(|e| e.to_string())?;
        let err = expect_broker_err(
            client.send_raw("approve", Some(&json!({ "requestId": request.request_id }))),
        )?;
        check(
            err.code == "bad_request",
            format!("codigo inesperado: {}", err.code),
        )
    });

    runner.test(
        "agente nao consegue cadastrar segredo sem a senha do cofre",
        || {
            let err = expect_broker_err(client.send_raw(
                "register_entry",
                Some(&json!({
                    "id": "INTRUSAO",
                    "kind": "generic",
                    "label": "invasor",
                    "targets": [server.base_url()],
                    "value": "valor-do-invasor"
                })),
            ))?;
            check(
                err.code == "bad_request",
                format!("codigo inesperado: {}", err.code),
            )
        },
    );

    runner.test("nenhum comando devolve segredo", || {
        for cmd in ["get_secret", "read_password", "list_secrets", "export"] {
            let err =
                expect_broker_err(client.send_raw(cmd, Some(&json!({ "id": "CPF_PESSOAL" }))))?;
            check(
                err.code == "bad_request",
                format!("comando {cmd} deveria ser desconhecido"),
            )?;
        }
        Ok(())
    });

    runner.test("TOTP habilitada exige codigo na aprovacao", || {
        let secret = Totp::generate_secret_default();
        totp_secret_holder = Some(secret.clone());
        client
            .set_totp(&secret, PASSPHRASE, None)
            .map_err(|e| e.to_string())?;

        let health = client.health().map_err(|e| e.to_string())?;
        check(health.totp_required, "a TOTP nao foi ativada")?;

        let request = client
            .request_operation("eco_teste", None)
            .map_err(|e| e.to_string())?;
        check(
            request.requires == "passphrase+totp",
            format!("requisicao inesperada: {}", request.requires),
        )?;

        let err = expect_broker_err(client.approve(&request.request_id, PASSPHRASE, None))?;
        check(
            err.code == "totp_required",
            format!("codigo inesperado: {}", err.code),
        )?;

        let wrong =
            expect_broker_err(client.approve(&request.request_id, PASSPHRASE, Some("000000")))?;
        check(
            wrong.code == "totp_invalid",
            format!("codigo inesperado: {}", wrong.code),
        )?;

        let code = Totp::generate_code(&secret, Utc::now())?;
        let approval = client
            .approve(&request.request_id, PASSPHRASE, Some(&code))
            .map_err(|e| e.to_string())?;
        check(
            approval.status.as_deref() == Some("completed"),
            format!("status inesperado: {:?}", approval.status),
        )
    });

    runner.test("revogacao remove a operacao", || {
        client
            .revoke_operation("eco_teste", PASSPHRASE)
            .map_err(|e| e.to_string())?;
        let ops = client.list_operations().map_err(|e| e.to_string())?;
        check(
            !ops.iter().any(|o| o.id == "eco_teste"),
            "a operacao revogada continua na lista",
        )
    });

    runner.test("remocao do registro apaga o segredo do cofre", || {
        client
            .delete_entry("SENHA_PORTAL_A", PASSPHRASE)
            .map_err(|e| e.to_string())?;
        let entries = client.list_entries().map_err(|e| e.to_string())?;
        check(
            !entries.iter().any(|e| e.id == "SENHA_PORTAL_A"),
            "o registro removido continua na lista",
        )
    });

    runner.test("o log do broker nao contem segredos", || {
        let log_path = home.join("logs").join("svault-broker.log");
        check(log_path.exists(), "o log nao foi criado")?;
        let log = fs::read_to_string(log_path).map_err(|e| e.to_string())?;
        check(!log.contains(SENHA_FAKE), "a senha vazou no log")?;
        check(!log.contains(CPF_FAKE), "o cpf vazou no log")?;
        check(!log.contains(PASSPHRASE), "a senha do cofre vazou no log")
    });

    runner.test("a senha do cofre e trocada re-rotulando os segredos", || {
        let nova = "nova-senha-de-teste-2026";
        let secret = totp_secret_holder.as_deref().unwrap();
        let code = Totp::generate_code(secret, Utc::now())?;
        client
            .change_passphrase(PASSPHRASE, nova, Some(&code))
            .map_err(|e| e.to_string())?;

        let request = client
            .request_operation("enviar_cpf", None)
            .map_err(|e| e.to_string())?;
        let err = expect_broker_err(client.approve(&request.request_id, PASSPHRASE, Some(&code)))?;
        check(
            err.code == "passphrase_invalid",
            format!("codigo inesperado: {}", err.code),
        )?;

        let approval = client
            .approve(&request.request_id, nova, Some(&code))
            .map_err(|e| e.to_string())?;
        check(
            approval.status.as_deref() == Some("completed"),
            format!("status inesperado: {:?}", approval.status),
        )?;
        let rendered = serde_json::to_string(&approval).unwrap();
        check(!rendered.contains(CPF_FAKE), "o cpf vazou no resultado")
    });
}

fn run_mcp_tests(runner: &mut Runner, mcp_exe: &Path, pipe_name: &str) {
    runner.test(
        "servidor MCP nativo em Rust expoe ferramentas seguras via stdio",
        || {
            let mut child = Command::new(mcp_exe)
                .env("SVAULT_PIPE", pipe_name)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .map_err(|e| format!("falha ao iniciar svault-mcp: {e}"))?;

            let mut stdin = child.stdin.take().unwrap();
            let mut stdout = BufReader::new(child.stdout.take().unwrap());

            fn rpc(
                stdin: &mut std::process::ChildStdin,
                stdout: &mut BufReader<std::process::ChildStdout>,
                id: i32,
                method: &str,
                params: Value,
            ) -> Result<Value, String> {
                let req = serde_json::to_string(&json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "method": method,
                    "params": params
                }))
                .unwrap();
                writeln!(stdin, "{req}").map_err(|e| e.to_string())?;
                stdin.flush().map_err(|e| e.to_string())?;

                let mut line = String::new();
                stdout.read_line(&mut line).map_err(|e| e.to_string())?;
                serde_json::from_str::<Value>(line.trim()).map_err(|e| e.to_string())
            }

            let res = (|| -> Result<(), String> {
                let init = rpc(
                    &mut stdin,
                    &mut stdout,
                    1,
                    "initialize",
                    json!({
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": { "name": "svault-smoke", "version": "1.0.0" }
                    }),
                )?;
                check(
                    init["result"]["serverInfo"]["name"].as_str() == Some("svault-mcp"),
                    "initialize nao retornou serverInfo svault-mcp",
                )?;

                writeln!(
                    stdin,
                    "{}",
                    json!({ "jsonrpc": "2.0", "method": "notifications/initialized", "params": {} })
                )
                .map_err(|e| e.to_string())?;
                stdin.flush().map_err(|e| e.to_string())?;

                let tools = rpc(&mut stdin, &mut stdout, 2, "tools/list", json!({}))?;
                let mut names: Vec<&str> = tools["result"]["tools"]
                    .as_array()
                    .ok_or("tools ausente")?
                    .iter()
                    .filter_map(|t| t["name"].as_str())
                    .collect();
                names.sort_unstable();
                check(
                    names
                        == vec![
                            "vault_health",
                            "vault_list_entries",
                            "vault_list_operations",
                            "vault_operation_status",
                            "vault_request_operation",
                        ],
                    format!("ferramentas inesperadas: {names:?}"),
                )?;

                let health = rpc(
                    &mut stdin,
                    &mut stdout,
                    3,
                    "tools/call",
                    json!({ "name": "vault_health", "arguments": {} }),
                )?;
                check(
                    health["result"]["isError"] != Value::Bool(true),
                    "vault_health retornou erro",
                )?;

                let entries = rpc(
                    &mut stdin,
                    &mut stdout,
                    4,
                    "tools/call",
                    json!({ "name": "vault_list_entries", "arguments": {} }),
                )?;
                let entries_text = entries["result"]["content"][0]["text"]
                    .as_str()
                    .unwrap_or("");
                check(
                    !entries_text.contains(CPF_FAKE) && !entries_text.contains(SENHA_FAKE),
                    "vault_list_entries vazou segredo",
                )?;

                let missing = rpc(
                    &mut stdin,
                    &mut stdout,
                    5,
                    "tools/call",
                    json!({
                        "name": "vault_request_operation",
                        "arguments": { "operationId": "inexistente" }
                    }),
                )?;
                let missing_text = missing["result"]["content"][0]["text"]
                    .as_str()
                    .unwrap_or("");
                check(
                    missing["result"]["isError"].as_bool() == Some(true)
                        && missing_text.contains("not_found"),
                    format!("erro inesperado em vault_request_operation: {missing_text}"),
                )?;

                Ok(())
            })();

            drop(stdin);
            let _ = child.kill();
            let _ = child.wait();
            res
        },
    );
}
