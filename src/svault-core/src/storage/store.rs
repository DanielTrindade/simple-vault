use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chrono::{SecondsFormat, Utc};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{ Base32, KEY_SIZE, Totp, VaultCrypto };
use crate::operations::OperationEngine;
use crate::paths;
use crate::protocol::error_codes;
use crate::storage::{
    CredentialManagerApi, CredentialStore, EntryRecord, OperationRecord, TargetPolicy, VaultError,
    VaultState, WindowsCredentialStore,
};

pub const ENTRY_TARGET_PREFIX: &str = "SVault:entry";
pub const TOTP_TARGET: &str = "SVault:totp";
pub const SECRET_USER_NAME: &str = "svault";

const KEY_CHECK_PLAINTEXT: &[u8] = b"svault-keycheck-v1";

fn now_iso() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true)
}

pub(crate) fn eq_ci(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b) || a.to_lowercase() == b.to_lowercase()
}

pub struct VaultStore {
    gate: Mutex<VaultState>,
    state_file: PathBuf,
    credentials: Arc<dyn CredentialStore>,
}

impl VaultStore {
    pub fn new(
        state_file: Option<PathBuf>,
        credentials: Option<Arc<dyn CredentialStore>>,
    ) -> Result<Self, VaultError> {
        let state_file = state_file.unwrap_or_else(|| paths::state_file(&paths::home()));
        let credentials = credentials.unwrap_or_else(|| Arc::new(WindowsCredentialStore));
        let initial = Self::load_from_disk(&state_file)?;
        Ok(Self {
            gate: Mutex::new(initial),
            state_file,
            credentials,
        })
    }

    pub fn state_path(&self) -> &Path {
        &self.state_file
    }

    pub fn state(&self) -> VaultState {
        let guard = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        guard.clone()
    }

    pub fn is_initialized(&self) -> bool {
        let guard = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        guard.initialized
    }

    pub fn totp_enabled(&self) -> bool {
        let guard = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        guard.totp_enabled && !guard.totp_secret.is_empty()
    }

    fn load_from_disk(state_file: &Path) -> io::Result<VaultState> {
        if !state_file.exists() {
            return Ok(VaultState::default());
        }
        let raw = fs::read_to_string(state_file)?;
        let cleaned = raw.strip_prefix('\u{feff}').unwrap_or(&raw);
        let parsed = serde_json::from_str::<VaultState>(cleaned).unwrap_or_default();
        Ok(parsed)
    }

    fn save_state_file(state_file: &Path, candidate: &VaultState) -> io::Result<()> {
        if let Some(parent) = state_file.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }

        let json = serde_json::to_string(candidate)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let temp_name = format!(
            "{}.{}.tmp",
            state_file
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("vault-state.json"),
            VaultCrypto::random_id()
        );
        let temp_path = state_file.with_file_name(temp_name);

        let write_result = (|| -> io::Result<()> {
            let mut opts = OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                opts.share_mode(0);
            }
            let mut file = opts.open(&temp_path)?;
            file.write_all(json.as_bytes())?;
            file.flush()?;
            file.sync_all()?;
            drop(file);

            atomic_replace(&temp_path, state_file)
        })();

        if write_result.is_err() && temp_path.exists() {
            let _ = fs::remove_file(&temp_path);
        }

        write_result
    }

    pub fn initialize(
        &self,
        passphrase: &str,
        enable_totp: bool,
        totp_secret: Option<&str>,
    ) -> Result<String, VaultError> {
        let mut state = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        Self::validate_new_passphrase(passphrase)?;
        if state.initialized {
            return Err(VaultError::new(
                error_codes::CONFLICT,
                "O cofre ja esta inicializado.",
            ));
        }

        let master_salt = VaultCrypto::random_salt();
        let vault_key = VaultCrypto::derive_vault_key(passphrase, &master_salt);

        let mut candidate = state.clone();
        candidate.master_salt = VaultCrypto::to_base64(&master_salt);
        candidate.key_check =
            VaultCrypto::to_base64(&VaultCrypto::seal(KEY_CHECK_PLAINTEXT, &vault_key));
        candidate.credential_generation = Some(VaultCrypto::random_id());
        candidate.initialized = true;

        let mut generated_totp = String::new();
        if enable_totp {
            generated_totp = match totp_secret.map(str::trim).filter(|s| !s.is_empty()) {
                Some(provided) => provided.to_owned(),
                None => Totp::generate_secret_default(),
            };
            Self::validate_totp_secret(&generated_totp)?;
            candidate.totp_secret =
                VaultCrypto::to_base64(&VaultCrypto::seal(generated_totp.as_bytes(), &vault_key));
            candidate.totp_enabled = true;
        }

        Self::save_state_file(&self.state_file, &candidate)?;
        *state = candidate;
        Ok(generated_totp)
    }

    pub fn verify_passphrase(&self, passphrase: &str) -> Result<bool, VaultError> {
        let state = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        if !state.initialized {
            return Ok(false);
        }
        let vault_key = Self::derive_vault_key_or_err(&state, passphrase)?;
        Ok(Self::key_check_matches(&state, &vault_key))
    }

    pub fn change_passphrase(
        &self,
        current_passphrase: &str,
        new_passphrase: &str,
        current_totp_code: Option<&str>,
    ) -> Result<(), VaultError> {
        let mut state = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        Self::validate_new_passphrase(new_passphrase)?;

        if !state.initialized {
            return Err(VaultError::new(
                error_codes::PASSPHRASE_INVALID,
                "Senha do cofre invalida.",
            ));
        }
        let vault_key = Self::derive_vault_key_or_err(&state, current_passphrase)?;
        if !Self::key_check_matches(&state, &vault_key) {
            return Err(VaultError::new(
                error_codes::PASSPHRASE_INVALID,
                "Senha do cofre invalida.",
            ));
        }

        Self::verify_current_totp(&state, &vault_key, current_totp_code)?;

        let new_master_salt = VaultCrypto::random_salt();
        let new_vault_key = VaultCrypto::derive_vault_key(new_passphrase, &new_master_salt);
        let new_generation = VaultCrypto::random_id();

        let mut staging_state = state.clone();
        let old_targets: Vec<String> = staging_state
            .entries
            .iter()
            .map(|e| {
                let ver = e
                    .credential_version
                    .as_deref()
                    .or(state.credential_generation.as_deref());
                Self::entry_target(&e.id, ver)
            })
            .collect();

        let legacy_targets: Vec<String> = staging_state
            .entries
            .iter()
            .filter(|e| {
                e.credential_version
                    .as_deref()
                    .or(state.credential_generation.as_deref())
                    .is_none_or(str::is_empty)
            })
            .map(|e| Self::entry_target(&e.id, None))
            .collect();

        let new_targets: Vec<String> = staging_state
            .entries
            .iter()
            .map(|e| Self::entry_target(&e.id, Some(&new_generation)))
            .collect();

        let mut known: Vec<String> = staging_state
            .known_credential_targets
            .iter()
            .filter(|t| !legacy_targets.iter().any(|l| l == *t))
            .cloned()
            .collect();
        for nt in new_targets {
            if !known.iter().any(|k| k == &nt) {
                known.push(nt);
            }
        }
        staging_state.known_credential_targets = known;
        Self::save_state_file(&self.state_file, &staging_state)?;
        *state = staging_state.clone();

        let mut candidate = staging_state;
        candidate.credential_generation = Some(new_generation.clone());
        for entry in &mut candidate.entries {
            entry.credential_version = None;
        }

        for entry in &candidate.entries {
            let original = state
                .entries
                .iter()
                .find(|e| eq_ci(&e.id, &entry.id))
                .expect("entry exists in staging state");
            let old_ver = original
                .credential_version
                .as_deref()
                .or(state.credential_generation.as_deref());
            let blob = self
                .credentials
                .read(&Self::entry_target(&entry.id, old_ver))?
                .ok_or_else(|| {
                    VaultError::new(
                        error_codes::NOT_FOUND,
                        format!("Segredo ausente: {}.", entry.id),
                    )
                })?;

            let salt = VaultCrypto::from_base64(&entry.entry_salt)
                .map_err(|_| VaultError::new(error_codes::INTERNAL, "Salt invalido."))?;
            let entry_key = VaultCrypto::derive_entry_key(&vault_key, &entry.id, &salt);
            let plaintext = VaultCrypto::try_open(&blob, &entry_key).ok_or_else(|| {
                VaultError::new(
                    error_codes::PASSPHRASE_INVALID,
                    "Falha ao abrir segredo durante rotacao.",
                )
            })?;

            let new_entry_key = VaultCrypto::derive_entry_key(&new_vault_key, &entry.id, &salt);
            let resealed = VaultCrypto::seal(&plaintext, &new_entry_key);
            let target_new = Self::entry_target(&entry.id, Some(&new_generation));
            self.credentials
                .write(&target_new, SECRET_USER_NAME, &resealed)?;

            let check = self.credentials.read(&target_new)?.ok_or_else(|| {
                VaultError::new(
                    error_codes::INTERNAL,
                    "Falha ao validar credencial durante rotacao.",
                )
            })?;
            let verified = VaultCrypto::try_open(&check, &new_entry_key).ok_or_else(|| {
                VaultError::new(
                    error_codes::INTERNAL,
                    "Falha ao validar credencial durante rotacao.",
                )
            })?;
            if !VaultCrypto::fixed_time_equals(&verified, &plaintext) {
                return Err(VaultError::new(
                    error_codes::INTERNAL,
                    "Falha ao validar credencial durante rotacao.",
                ));
            }
        }

        candidate.master_salt = VaultCrypto::to_base64(&new_master_salt);
        candidate.key_check =
            VaultCrypto::to_base64(&VaultCrypto::seal(KEY_CHECK_PLAINTEXT, &new_vault_key));

        if candidate.totp_enabled && !candidate.totp_secret.is_empty() {
            let env = VaultCrypto::from_base64(&candidate.totp_secret)
                .map_err(|_| VaultError::new(error_codes::INTERNAL, "Segredo TOTP corrompido."))?;
            let totp_plain = VaultCrypto::try_open(&env, &vault_key).ok_or_else(|| {
                VaultError::new(
                    error_codes::PASSPHRASE_INVALID,
                    "Falha ao abrir o segredo TOTP durante rotacao.",
                )
            })?;
            candidate.totp_secret =
                VaultCrypto::to_base64(&VaultCrypto::seal(&totp_plain, &new_vault_key));
        }

        Self::save_state_file(&self.state_file, &candidate)?;
        *state = candidate.clone();

        for target in old_targets {
            if self.credentials.delete(&target).is_ok()
                && state
                    .credential_generation
                    .as_deref()
                    .is_some_and(|g| !g.is_empty())
            {
                let mut cleanup_state = state.clone();
                cleanup_state
                    .known_credential_targets
                    .retain(|t| t != &target);
                if Self::save_state_file(&self.state_file, &cleanup_state).is_ok() {
                    *state = cleanup_state.clone();
                    candidate = cleanup_state;
                }
            }
        }

        if Self::save_state_file(&self.state_file, &candidate).is_ok() {
            *state = candidate;
        }

        Ok(())
    }

    pub fn register_entry(
        &self,
        id: &str,
        kind: &str,
        label: &str,
        targets: &[String],
        value: &[u8],
        passphrase: &str,
    ) -> Result<EntryRecord, VaultError> {
        let mut state = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        let vault_key = Self::require_vault_key(&state, passphrase)?;

        if state.entries.iter().any(|e| eq_ci(&e.id, id)) {
            return Err(VaultError::new(
                error_codes::CONFLICT,
                format!("Ja existe um registro com o identificador {id}."),
            ));
        }

        let entry_salt = VaultCrypto::random_salt();
        let entry_key = VaultCrypto::derive_entry_key(&vault_key, id, &entry_salt);
        let sealed_value = VaultCrypto::seal(value, &entry_key);

        let target = Self::entry_target(id, state.credential_generation.as_deref());
        if !state.known_credential_targets.iter().any(|t| t == &target) {
            state.known_credential_targets.push(target.clone());
            Self::save_state_file(&self.state_file, &state)?;
        }

        self.credentials
            .write(&target, SECRET_USER_NAME, &sealed_value)?;

        let now = now_iso();
        let record = EntryRecord {
            identity_id: VaultCrypto::random_id(),
            id: id.to_owned(),
            kind: kind.to_owned(),
            label: label.to_owned(),
            targets: targets.to_vec(),
            created_at: now.clone(),
            updated_at: now,
            revision: 1,
            entry_salt: VaultCrypto::to_base64(&entry_salt),
            credential_version: None,
        };

        let mut candidate = state.clone();
        candidate.entries.push(record.clone());
        Self::save_state_file(&self.state_file, &candidate)?;
        *state = candidate;
        Ok(record)
    }

    pub fn update_entry(
        &self,
        id: &str,
        value: Option<&[u8]>,
        label: Option<&str>,
        targets: Option<&[String]>,
        passphrase: &str,
    ) -> Result<EntryRecord, VaultError> {
        let mut state = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        let vault_key = Self::require_vault_key(&state, passphrase)?;

        let current_idx = state
            .entries
            .iter()
            .position(|e| eq_ci(&e.id, id))
            .ok_or_else(|| {
                VaultError::new(
                    error_codes::NOT_FOUND,
                    format!("Registro nao encontrado: {id}."),
                )
            })?;

        let old_target = {
            let current = &state.entries[current_idx];
            let ver = current
                .credential_version
                .as_deref()
                .or(state.credential_generation.as_deref());
            Self::entry_target(&current.id, ver)
        };

        let mut candidate = state.clone();
        if let Some(new_val) = value {
            let record_id = candidate.entries[current_idx].id.clone();
            let salt = VaultCrypto::from_base64(&candidate.entries[current_idx].entry_salt)
                .map_err(|_| VaultError::new(error_codes::INTERNAL, "Salt invalido."))?;
            let entry_key = VaultCrypto::derive_entry_key(&vault_key, &record_id, &salt);
            let version = format!("entry-{}", VaultCrypto::random_id());
            let new_target = Self::entry_target(&record_id, Some(&version));

            if !state
                .known_credential_targets
                .iter()
                .any(|t| t == &new_target)
            {
                let mut staging = state.clone();
                staging.known_credential_targets.push(new_target.clone());
                Self::save_state_file(&self.state_file, &staging)?;
                *state = staging.clone();
                candidate = staging;
            }

            self.credentials.write(
                &new_target,
                SECRET_USER_NAME,
                &VaultCrypto::seal(new_val, &entry_key),
            )?;
            candidate.entries[current_idx].credential_version = Some(version);
        }

        let record = &mut candidate.entries[current_idx];
        if let Some(new_label) = label {
            record.label = new_label.to_owned();
        }
        if let Some(new_targets) = targets {
            record.targets = new_targets.to_vec();
        }
        record.updated_at = now_iso();
        record.revision += 1;
        let updated_record = record.clone();

        Self::save_state_file(&self.state_file, &candidate)?;
        *state = candidate;

        if value.is_some() && self.credentials.delete(&old_target).is_ok() {
            let mut cleanup_state = state.clone();
            cleanup_state
                .known_credential_targets
                .retain(|t| t != &old_target);
            if Self::save_state_file(&self.state_file, &cleanup_state).is_ok() {
                *state = cleanup_state;
            }
        }

        Ok(updated_record)
    }

    pub fn delete_entry(&self, id: &str, passphrase: &str) -> Result<(), VaultError> {
        let mut state = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        let _vault_key = Self::require_vault_key(&state, passphrase)?;

        let record = state
            .entries
            .iter()
            .find(|e| eq_ci(&e.id, id))
            .cloned()
            .ok_or_else(|| {
                VaultError::new(
                    error_codes::NOT_FOUND,
                    format!("Registro nao encontrado: {id}."),
                )
            })?;

        let old_ver = record
            .credential_version
            .as_deref()
            .or(state.credential_generation.as_deref());
        let old_target = Self::entry_target(&record.id, old_ver);

        let mut candidate = state.clone();
        candidate.entries.retain(|e| !eq_ci(&e.id, &record.id));
        candidate
            .operations
            .retain(|o| !eq_ci(&o.entry_id, &record.id));
        Self::save_state_file(&self.state_file, &candidate)?;
        *state = candidate;

        if self.credentials.delete(&old_target).is_ok() {
            let mut cleanup_state = state.clone();
            cleanup_state
                .known_credential_targets
                .retain(|t| t != &old_target);
            if Self::save_state_file(&self.state_file, &cleanup_state).is_ok() {
                *state = cleanup_state;
            }
        }

        Ok(())
    }

    pub fn unwrap_secret(
        &self,
        entry_id: &str,
        passphrase: &str,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let state = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        let vault_key = Self::require_vault_key(&state, passphrase)?;

        let record = state
            .entries
            .iter()
            .find(|e| eq_ci(&e.id, entry_id))
            .ok_or_else(|| {
                VaultError::new(
                    error_codes::NOT_FOUND,
                    format!("Registro nao encontrado: {entry_id}."),
                )
            })?;

        let ver = record
            .credential_version
            .as_deref()
            .or(state.credential_generation.as_deref());
        let blob = self
            .credentials
            .read(&Self::entry_target(&record.id, ver))?
            .ok_or_else(|| {
                VaultError::new(
                    error_codes::NOT_FOUND,
                    format!("Segredo ausente: {entry_id}."),
                )
            })?;

        let salt = VaultCrypto::from_base64(&record.entry_salt)
            .map_err(|_| VaultError::new(error_codes::INTERNAL, "Salt invalido."))?;
        let entry_key = VaultCrypto::derive_entry_key(&vault_key, &record.id, &salt);
        VaultCrypto::try_open(&blob, &entry_key).ok_or_else(|| {
            VaultError::new(
                error_codes::PASSPHRASE_INVALID,
                "Nao foi possivel descriptografar o segredo.",
            )
        })
    }

    pub fn unwrap_all_secrets(
        &self,
        passphrase: &str,
    ) -> Result<HashMap<String, Zeroizing<Vec<u8>>>, VaultError> {
        let state = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        let vault_key = Self::require_vault_key(&state, passphrase)?;
        let mut result = HashMap::new();

        for record in &state.entries {
            let ver = record
                .credential_version
                .as_deref()
                .or(state.credential_generation.as_deref());
            let Some(blob) = self
                .credentials
                .read(&Self::entry_target(&record.id, ver))?
            else {
                continue;
            };
            let Ok(salt) = VaultCrypto::from_base64(&record.entry_salt) else {
                continue;
            };
            let entry_key = VaultCrypto::derive_entry_key(&vault_key, &record.id, &salt);
            if let Some(plaintext) = VaultCrypto::try_open(&blob, &entry_key) {
                result.insert(record.id.clone(), plaintext);
            }
        }

        Ok(result)
    }

    pub fn unwrap_secrets<'a, I>(
        &self,
        entry_ids: I,
        passphrase: &str,
    ) -> Result<HashMap<String, Zeroizing<Vec<u8>>>, VaultError>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let state = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        let vault_key = Self::require_vault_key(&state, passphrase)?;
        let mut result = HashMap::new();

        for id in entry_ids {
            let Some(record) = state.entries.iter().find(|e| eq_ci(&e.id, id)) else {
                continue;
            };
            let ver = record
                .credential_version
                .as_deref()
                .or(state.credential_generation.as_deref());
            let Some(blob) = self
                .credentials
                .read(&Self::entry_target(&record.id, ver))?
            else {
                continue;
            };
            let Ok(salt) = VaultCrypto::from_base64(&record.entry_salt) else {
                continue;
            };
            let entry_key = VaultCrypto::derive_entry_key(&vault_key, &record.id, &salt);
            if let Some(plaintext) = VaultCrypto::try_open(&blob, &entry_key) {
                result.insert(record.id.clone(), plaintext);
            }
        }

        Ok(result)
    }

    pub fn reset(
        &self,
        passphrase: &str,
        current_totp_code: Option<&str>,
    ) -> Result<usize, VaultError> {
        let mut state = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        let vault_key = Self::require_vault_key(&state, passphrase)?;
        Self::verify_current_totp(&state, &vault_key, current_totp_code)?;
        drop(vault_key);

        let mut owned_targets = state.known_credential_targets.clone();
        for entry in &state.entries {
            let ver = entry
                .credential_version
                .as_deref()
                .or(state.credential_generation.as_deref());
            let target = Self::entry_target(&entry.id, ver);
            if !owned_targets.iter().any(|t| t == &target) {
                owned_targets.push(target);
            }
        }

        for target in owned_targets {
            let _ = self.credentials.delete(&target);
        }

        let removed = state.entries.len();
        let reset_state = VaultState::default();
        Self::save_state_file(&self.state_file, &reset_state)?;
        *state = reset_state;
        Ok(removed)
    }

    pub fn authorize_operation(
        &self,
        mut record: OperationRecord,
        passphrase: &str,
    ) -> Result<OperationRecord, VaultError> {
        OperationEngine::validate_templates(&record)
            .map_err(|e| VaultError::new(error_codes::BAD_REQUEST, e.message))?;

        let mut state = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        let _vault_key = Self::require_vault_key(&state, passphrase)?;

        if state.operations.iter().any(|o| eq_ci(&o.id, &record.id)) {
            return Err(VaultError::new(
                error_codes::CONFLICT,
                format!("Ja existe uma operacao com o identificador {}.", record.id),
            ));
        }

        let entry = state
            .entries
            .iter()
            .find(|e| eq_ci(&e.id, &record.entry_id))
            .ok_or_else(|| {
                VaultError::new(
                    error_codes::NOT_FOUND,
                    format!("Registro nao encontrado: {}.", record.entry_id),
                )
            })?;

        if record.action != OperationEngine::ACTION_NOOP_ECHO
            && !TargetPolicy::is_target_allowed(&entry.targets, &record.target)
        {
            return Err(VaultError::new(
                error_codes::TARGET_NOT_ALLOWED,
                format!(
                    "O alvo {} nao esta autorizado para o registro {}.",
                    record.target, entry.id
                ),
            ));
        }

        if record.authorization_id.trim().is_empty() {
            record.authorization_id = VaultCrypto::random_id();
        }

        let mut candidate = state.clone();
        candidate.operations.push(record.clone());
        Self::save_state_file(&self.state_file, &candidate)?;
        *state = candidate;
        Ok(record)
    }

    pub fn revoke_operation(&self, operation_id: &str, passphrase: &str) -> Result<(), VaultError> {
        let mut state = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        let _vault_key = Self::require_vault_key(&state, passphrase)?;

        if !state.operations.iter().any(|o| eq_ci(&o.id, operation_id)) {
            return Err(VaultError::new(
                error_codes::NOT_FOUND,
                format!("Operacao nao encontrada: {operation_id}"),
            ));
        }

        let mut candidate = state.clone();
        candidate
            .operations
            .retain(|o| !eq_ci(&o.id, operation_id));
        Self::save_state_file(&self.state_file, &candidate)?;
        *state = candidate;
        Ok(())
    }

    pub fn set_totp(
        &self,
        secret: &str,
        passphrase: &str,
        current_totp_code: Option<&str>,
    ) -> Result<(), VaultError> {
        let mut state = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        let vault_key = Self::require_vault_key(&state, passphrase)?;
        Self::verify_current_totp(&state, &vault_key, current_totp_code)?;

        let trimmed = secret.trim();
        Self::validate_totp_secret(trimmed)?;

        let mut candidate = state.clone();
        candidate.totp_secret =
            VaultCrypto::to_base64(&VaultCrypto::seal(trimmed.as_bytes(), &vault_key));
        candidate.totp_enabled = true;
        Self::save_state_file(&self.state_file, &candidate)?;
        *state = candidate;
        Ok(())
    }

    pub fn disable_totp(
        &self,
        passphrase: &str,
        current_totp_code: Option<&str>,
    ) -> Result<(), VaultError> {
        let mut state = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        let vault_key = Self::require_vault_key(&state, passphrase)?;
        Self::verify_current_totp(&state, &vault_key, current_totp_code)?;

        let mut candidate = state.clone();
        candidate.totp_secret = String::new();
        candidate.totp_enabled = false;
        Self::save_state_file(&self.state_file, &candidate)?;
        *state = candidate;
        Ok(())
    }

    pub fn get_totp_secret(&self, passphrase: &str) -> Result<Option<Zeroizing<String>>, VaultError> {
        let state = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        if !state.totp_enabled || state.totp_secret.is_empty() {
            return Ok(None);
        }

        let vault_key = Self::require_vault_key(&state, passphrase)?;
        let Ok(env) = VaultCrypto::from_base64(&state.totp_secret) else {
            return Ok(None);
        };
        let Some(mut opened) = VaultCrypto::try_open(&env, &vault_key) else {
            return Ok(None);
        };

        let secret = String::from_utf8_lossy(&opened).into_owned();
        opened.zeroize();
        Ok(Some(Zeroizing::new(secret)))
    }

    fn verify_current_totp(
        state: &VaultState,
        vault_key: &[u8; KEY_SIZE],
        code: Option<&str>,
    ) -> Result<(), VaultError> {
        if !state.totp_enabled || state.totp_secret.is_empty() {
            return Ok(());
        }

        let env = VaultCrypto::from_base64(&state.totp_secret).map_err(|_| {
            VaultError::new(
                error_codes::INTERNAL,
                "Falha ao verificar o segundo fator.",
            )
        })?;
        let secret_bytes = VaultCrypto::try_open(&env, vault_key).ok_or_else(|| {
            VaultError::new(
                error_codes::INTERNAL,
                "Falha ao verificar o segundo fator.",
            )
        })?;

        let secret = std::str::from_utf8(&secret_bytes).map_err(|_| {
            VaultError::new(
                error_codes::INTERNAL,
                "Falha ao verificar o segundo fator.",
            )
        })?;

        let Some(provided) = code.filter(|c| !c.trim().is_empty()) else {
            return Err(VaultError::new(
                error_codes::TOTP_INVALID,
                "Codigo do segundo fator invalido.",
            ));
        };

        if !Totp::verify_code(secret, provided, Utc::now()) {
            return Err(VaultError::new(
                error_codes::TOTP_INVALID,
                "Codigo do segundo fator invalido.",
            ));
        }

        Ok(())
    }

    fn validate_new_passphrase(passphrase: &str) -> Result<(), VaultError> {
        if passphrase.trim().is_empty() || passphrase.chars().count() < 8 {
            return Err(VaultError::new(
                error_codes::BAD_REQUEST,
                "A nova senha deve ter pelo menos oito caracteres.",
            ));
        }
        Ok(())
    }

    fn validate_totp_secret(secret: &str) -> Result<(), VaultError> {
        let decoded = Base32::decode(secret).map_err(|_| {
            VaultError::new(
                error_codes::BAD_REQUEST,
                "O segredo TOTP tem formato invalido.",
            )
        })?;
        if decoded.len() < 16 {
            return Err(VaultError::new(
                error_codes::BAD_REQUEST,
                "O segredo TOTP deve conter ao menos 16 bytes codificados.",
            ));
        }
        Ok(())
    }

    fn entry_target(id: &str, generation: Option<&str>) -> String {
        match generation.filter(|g| !g.is_empty()) {
            Some(g) => CredentialManagerApi::build_target(&format!("{ENTRY_TARGET_PREFIX}:{g}"), id),
            None => CredentialManagerApi::build_target(ENTRY_TARGET_PREFIX, id),
        }
    }

    fn derive_vault_key_or_err(
        state: &VaultState,
        passphrase: &str,
    ) -> Result<Zeroizing<[u8; KEY_SIZE]>, VaultError> {
        if passphrase.is_empty() {
            return Err(VaultError::new(
                error_codes::PASSPHRASE_REQUIRED,
                "Senha do cofre obrigatoria.",
            ));
        }
        let master_salt = VaultCrypto::from_base64(&state.master_salt)
            .map_err(|_| VaultError::new(error_codes::INTERNAL, "Master salt invalido."))?;
        Ok(VaultCrypto::derive_vault_key(passphrase, &master_salt))
    }

    fn require_vault_key(
        state: &VaultState,
        passphrase: &str,
    ) -> Result<Zeroizing<[u8; KEY_SIZE]>, VaultError> {
        if !state.initialized {
            return Err(VaultError::new(
                error_codes::VAULT_NOT_INITIALIZED,
                "Cofre ainda nao inicializado.",
            ));
        }
        let vault_key = Self::derive_vault_key_or_err(state, passphrase)?;
        if !Self::key_check_matches(state, &vault_key) {
            return Err(VaultError::new(
                error_codes::PASSPHRASE_INVALID,
                "Senha do cofre invalida.",
            ));
        }
        Ok(vault_key)
    }

    fn key_check_matches(state: &VaultState, vault_key: &[u8; KEY_SIZE]) -> bool {
        let Ok(env) = VaultCrypto::from_base64(&state.key_check) else {
            return false;
        };
        let Some(opened) = VaultCrypto::try_open(&env, vault_key) else {
            return false;
        };
        VaultCrypto::fixed_time_equals(&opened, KEY_CHECK_PLAINTEXT)
    }
}

#[cfg(windows)]
fn atomic_replace(src: &Path, dst: &Path) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_REPLACE_EXISTING, MoveFileExW};

    use crate::storage::credman::wide_null;

    let src_wide = wide_null(&src.to_string_lossy());
    let dst_wide = wide_null(&dst.to_string_lossy());
    let ok = unsafe { MoveFileExW(src_wide.as_ptr(), dst_wide.as_ptr(), MOVEFILE_REPLACE_EXISTING) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(windows))]
fn atomic_replace(src: &Path, dst: &Path) -> io::Result<()> {
    fs::rename(src, dst)
}
