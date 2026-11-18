pub mod credman;
pub mod lsa;
pub mod state;
pub mod store;
pub mod target_policy;

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::sync::Mutex;

pub use credman::{CredentialManagerApi, WindowsCredentialStore};
pub use lsa::LsaRights;
pub use state::{EntryRecord, HttpRequestRecord, OperationRecord, ProcessRecord, VaultState};
pub use store::VaultStore;
pub use target_policy::TargetPolicy;

#[derive(Debug)]
pub enum VaultError {
    Vault { code: String, message: String },
    Io(io::Error),
}

impl VaultError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Vault {
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn code(&self) -> Option<&str> {
        match self {
            Self::Vault { code, .. } => Some(code.as_str()),
            Self::Io(_) => None,
        }
    }
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vault { message, .. } => f.write_str(message),
            Self::Io(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<io::Error> for VaultError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

pub trait CredentialStore: Send + Sync {
    fn write(&self, target: &str, user_name: &str, secret: &[u8]) -> io::Result<()>;
    fn read(&self, target: &str) -> io::Result<Option<Vec<u8>>>;
    fn delete(&self, target: &str) -> io::Result<()>;
    fn list_targets(&self, filter: &str) -> io::Result<Vec<String>>;
}

#[derive(Default)]
pub struct MemoryCredentialStore {
    items: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemoryCredentialStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl CredentialStore for MemoryCredentialStore {
    fn write(&self, target: &str, _user_name: &str, secret: &[u8]) -> io::Result<()> {
        let mut items = self.items.lock().unwrap_or_else(|e| e.into_inner());
        items.insert(target.to_owned(), secret.to_vec());
        Ok(())
    }

    fn read(&self, target: &str) -> io::Result<Option<Vec<u8>>> {
        let items = self.items.lock().unwrap_or_else(|e| e.into_inner());
        Ok(items.get(target).cloned())
    }

    fn delete(&self, target: &str) -> io::Result<()> {
        let mut items = self.items.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(mut old) = items.remove(target) {
            use zeroize::Zeroize;
            old.zeroize();
        }
        Ok(())
    }

    fn list_targets(&self, filter: &str) -> io::Result<Vec<String>> {
        let items = self.items.lock().unwrap_or_else(|e| e.into_inner());
        let mut out: Vec<String> = items
            .keys()
            .filter(|k| k.starts_with(filter))
            .cloned()
            .collect();
        out.sort();
        Ok(out)
    }
}
