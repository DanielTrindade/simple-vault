use std::env;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use serde_json::json;
use tokio::sync::watch;

use svault_broker::engine::BrokerEngine;
use svault_broker::pipe_server::{PipeSecurityDescriptor, PipeServer, current_process_sid};
use svault_broker::service_identity;
use svault_core::config::BrokerConfig;
use svault_core::logging::VaultLog;
use svault_core::paths;
use svault_core::storage::{CredentialStore, MemoryCredentialStore, VaultStore};

const SERVICE_NAME: &str = "SVaultBroker";

#[derive(Debug, Clone)]
struct BrokerOptions {
    console: bool,
    home: PathBuf,
    config_path: PathBuf,
    state_path: PathBuf,
    log_path: PathBuf,
    pipe_name: String,
    in_memory_credentials: bool,
}

impl BrokerOptions {
    fn parse(args: &[String]) -> Result<Self, String> {
        let console = args.iter().any(|a| a.eq_ignore_ascii_case("--console"));
        let in_memory_credentials = args
            .iter()
            .any(|a| a.eq_ignore_ascii_case("--in-memory-credentials"));

        if in_memory_credentials && !console {
            return Err("O armazenamento em memoria so pode ser usado em modo console.".to_owned());
        }

        let home_arg = get_arg_value(args, "--home");
        let config_arg = get_arg_value(args, "--config");
        let state_arg = get_arg_value(args, "--state");
        let log_arg = get_arg_value(args, "--log");
        let pipe_arg = get_arg_value(args, "--pipe");

        let home = if let Some(h) = home_arg.filter(|s| !s.trim().is_empty()) {
            PathBuf::from(h)
        } else if let Ok(env_h) = env::var(paths::ENV_HOME)
            && !env_h.trim().is_empty()
        {
            PathBuf::from(env_h.trim())
        } else if console {
            paths::local_home()
        } else {
            paths::home()
        };

        let config_path = config_arg
            .map(PathBuf::from)
            .unwrap_or_else(|| paths::config_file(&home));
        let state_path = state_arg
            .map(PathBuf::from)
            .unwrap_or_else(|| paths::state_file(&home));
        let log_path = log_arg
            .map(PathBuf::from)
            .unwrap_or_else(|| paths::log_file(&home));
        let pipe_name = pipe_arg
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().to_owned())
            .unwrap_or_else(|| paths::PIPE_NAME.to_owned());

        Ok(Self {
            console,
            home,
            config_path,
            state_path,
            log_path,
            pipe_name,
            in_memory_credentials,
        })
    }
}

fn get_arg_value(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a.eq_ignore_ascii_case(name))
        .and_then(|idx| args.get(idx + 1))
        .cloned()
}

struct PreparedRuntime {
    options: BrokerOptions,
    store: Arc<VaultStore>,
    log: Arc<VaultLog>,
    server: PipeServer,
}

fn prepare_runtime(options: BrokerOptions) -> Result<PreparedRuntime, String> {
    let _ = paths::ensure_directories(&options.home);

    let config = BrokerConfig::load(Some(&options.config_path));
    let log = Arc::new(VaultLog::new(Some(&options.log_path)));
    let creds: Option<Arc<dyn CredentialStore>> = if options.in_memory_credentials {
        Some(Arc::new(MemoryCredentialStore::new()))
    } else {
        None
    };

    let store = Arc::new(
        VaultStore::new(Some(options.state_path.clone()), creds)
            .map_err(|e| format!("Falha ao inicializar VaultStore: {e}"))?,
    );
    let engine = Arc::new(BrokerEngine::new(
        Arc::clone(&store),
        Arc::clone(&log),
        config.clone(),
    ));

    let owner_sid = current_process_sid().unwrap_or_default();
    let mut allowed_sids = config.allowed_client_sids.clone();
    if !owner_sid.is_empty() && !allowed_sids.iter().any(|s| s.eq_ignore_ascii_case(&owner_sid)) {
        allowed_sids.push(owner_sid.clone());
    }

    let security = Arc::new(
        PipeSecurityDescriptor::build(&owner_sid, &allowed_sids)
            .map_err(|e| format!("Falha ao configurar DACL do pipe: {e}"))?,
    );

    let server = PipeServer::new(&options.pipe_name, security, engine, Arc::clone(&log));

    Ok(PreparedRuntime {
        options,
        store,
        log,
        server,
    })
}

fn main() -> ExitCode {
    let raw_args: Vec<String> = env::args().skip(1).collect();
    let options = match BrokerOptions::parse(&raw_args) {
        Ok(opts) => opts,
        Err(msg) => {
            eprintln!("erro: {msg}");
            return ExitCode::from(1);
        }
    };

    if options.console {
        if let Err(msg) = run_console(options) {
            eprintln!("erro: {msg}");
            return ExitCode::from(1);
        }
        return ExitCode::SUCCESS;
    }

    #[cfg(windows)]
    {
        if let Err(err) = windows_service_host::start() {
            eprintln!("erro ao iniciar servico Windows {SERVICE_NAME}: {err}");
            return ExitCode::from(1);
        }
        ExitCode::SUCCESS
    }
}

fn run_console(options: BrokerOptions) -> Result<(), String> {
    let prepared = prepare_runtime(options)?;

    println!("SVault broker em modo console.");
    println!("  home      : {}", prepared.options.home.display());
    println!(
        "  pipe      : {}",
        paths::pipe_path(&prepared.options.pipe_name)
    );
    println!("  identidade: {}", service_identity());
    println!(
        "  cofre     : {}",
        if prepared.store.is_initialized() {
            "inicializado"
        } else {
            "nao inicializado"
        }
    );
    println!("Pressione Ctrl+C para encerrar.");

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Falha ao iniciar runtime async: {e}"))?;

    rt.block_on(async move {
        prepared.log.write(
            "broker_started",
            [
                ("identity", json!(service_identity())),
                ("pipe", json!(prepared.options.pipe_name)),
            ],
        );

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            let _ = shutdown_tx.send(true);
        });

        prepared
            .server
            .run(shutdown_rx)
            .await
            .map_err(|e| format!("Falha no servidor de pipe: {e}"))
    })
}

#[cfg(windows)]
mod windows_service_host {
    use std::ffi::OsString;
    use std::time::Duration;

    use serde_json::json;
    use tokio::sync::watch;
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::{define_windows_service, service_dispatcher};

    use super::{BrokerOptions, SERVICE_NAME, prepare_runtime};
    use svault_broker::service_identity;

    define_windows_service!(ffi_service_main, service_main);

    pub fn start() -> windows_service::Result<()> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
    }

    fn service_main(_arguments: Vec<OsString>) {
        let _ = run_service();
    }

    fn run_service() -> Result<(), String> {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let status_handle =
            service_control_handler::register(SERVICE_NAME, move |control_event| match control_event
            {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    let _ = shutdown_tx.send(true);
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            })
            .map_err(|e| e.to_string())?;

        let report_status = |current_state: ServiceState,
                             controls_accepted: ServiceControlAccept,
                             exit_code: u32,
                             wait_hint: Duration| {
            let _ = status_handle.set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state,
                controls_accepted,
                exit_code: if exit_code == 0 {
                    ServiceExitCode::Win32(0)
                } else {
                    ServiceExitCode::ServiceSpecific(exit_code)
                },
                checkpoint: 0,
                wait_hint,
                process_id: None,
            });
        };

        report_status(
            ServiceState::StartPending,
            ServiceControlAccept::empty(),
            0,
            Duration::from_secs(10),
        );

        let raw_args: Vec<String> = std::env::args().skip(1).collect();
        let options = match BrokerOptions::parse(&raw_args) {
            Ok(opts) => opts,
            Err(err) => {
                report_status(
                    ServiceState::Stopped,
                    ServiceControlAccept::empty(),
                    1,
                    Duration::ZERO,
                );
                return Err(err);
            }
        };

        let prepared = match prepare_runtime(options) {
            Ok(p) => p,
            Err(err) => {
                report_status(
                    ServiceState::Stopped,
                    ServiceControlAccept::empty(),
                    2,
                    Duration::ZERO,
                );
                return Err(err);
            }
        };

        let rt = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(err) => {
                report_status(
                    ServiceState::Stopped,
                    ServiceControlAccept::empty(),
                    3,
                    Duration::ZERO,
                );
                return Err(err.to_string());
            }
        };

        prepared.log.write(
            "broker_started",
            [
                ("identity", json!(service_identity())),
                ("pipe", json!(prepared.options.pipe_name)),
            ],
        );

        report_status(
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            0,
            Duration::ZERO,
        );

        let result = rt.block_on(prepared.server.run(shutdown_rx));

        report_status(
            ServiceState::StopPending,
            ServiceControlAccept::empty(),
            0,
            Duration::from_secs(5),
        );
        drop(rt);

        let exit_code = if result.is_ok() { 0 } else { 4 };
        report_status(
            ServiceState::Stopped,
            ServiceControlAccept::empty(),
            exit_code,
            Duration::ZERO,
        );

        result.map_err(|e| e.to_string())
    }
}
