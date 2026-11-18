use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const PIPE_NAME: &str = "svault.broker.v1";
pub const ENV_HOME: &str = "SVAULT_HOME";
pub const ENV_PIPE: &str = "SVAULT_PIPE";

pub fn home() -> PathBuf {
    if let Ok(configured) = env::var(ENV_HOME) {
        let trimmed = configured.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }

    let program_data = env::var("PROGRAMDATA")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| r"C:\ProgramData".to_owned());
    PathBuf::from(program_data).join("SVault")
}

pub fn local_home() -> PathBuf {
    let local_app_data = env::var("LOCALAPPDATA")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| r"C:\ProgramData".to_owned());
    PathBuf::from(local_app_data).join("SVault")
}

pub fn state_dir(home: &Path) -> PathBuf {
    home.join("state")
}

pub fn state_file(home: &Path) -> PathBuf {
    state_dir(home).join("vault-state.json")
}

pub fn log_dir(home: &Path) -> PathBuf {
    home.join("logs")
}

pub fn log_file(home: &Path) -> PathBuf {
    log_dir(home).join("svault-broker.log")
}

pub fn config_file(home: &Path) -> PathBuf {
    home.join("broker.json")
}

pub fn pipe_path(pipe_name: &str) -> String {
    let trimmed = pipe_name.trim();
    if trimmed.starts_with(r"\\") {
        trimmed.to_owned()
    } else {
        format!(r"\\.\pipe\{trimmed}")
    }
}

pub fn ensure_directories(home: &Path) -> io::Result<()> {
    fs::create_dir_all(state_dir(home))?;
    fs::create_dir_all(log_dir(home))?;
    Ok(())
}
