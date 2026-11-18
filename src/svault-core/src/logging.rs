use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::{SecondsFormat, Utc};
use serde_json::{Map, Value};

use crate::paths;

/// Event log for the broker. Only identifiers, targets and outcomes are recorded:
/// never secret values, never parameter values, never request bodies.
pub struct VaultLog {
    file: PathBuf,
    gate: Mutex<()>,
}

impl VaultLog {
    pub fn new(file: Option<&Path>) -> Self {
        Self {
            file: file
                .map(Path::to_path_buf)
                .unwrap_or_else(|| paths::log_file(&paths::home())),
            gate: Mutex::new(()),
        }
    }

    pub fn write<I, K>(&self, event_name: &str, fields: I)
    where
        I: IntoIterator<Item = (K, Value)>,
        K: Into<String>,
    {
        let mut payload = Map::new();
        payload.insert(
            "ts".to_owned(),
            Value::String(Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true)),
        );
        payload.insert("event".to_owned(), Value::String(event_name.to_owned()));
        for (key, value) in fields {
            if !value.is_null() {
                payload.insert(key.into(), value);
            }
        }

        let Ok(line) = serde_json::to_string(&Value::Object(payload)) else {
            return;
        };

        let _guard = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(parent) = self.file.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&self.file) {
            let _ = writeln!(f, "{line}");
        }
    }
}
