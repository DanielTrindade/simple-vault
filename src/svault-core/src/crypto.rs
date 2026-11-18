use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub const SALT_SIZE: usize = 16;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;
pub const KEY_SIZE: usize = 32;
pub const KDF_ITERATIONS: u32 = 210_000;

pub struct VaultCrypto;

impl VaultCrypto {
    pub fn random_bytes(len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        getrandom::getrandom(&mut buf).expect("CSPRNG do sistema operacional indisponivel");
        buf
    }

    pub fn random_salt() -> [u8; SALT_SIZE] {
        let mut buf = [0u8; SALT_SIZE];
        getrandom::getrandom(&mut buf).expect("CSPRNG do sistema operacional indisponivel");
        buf
    }

    pub fn random_nonce() -> [u8; NONCE_SIZE] {
        let mut buf = [0u8; NONCE_SIZE];
        getrandom::getrandom(&mut buf).expect("CSPRNG do sistema operacional indisponivel");
        buf
    }

    /// Generates a 32-character lowercase hex identifier (128 bits of entropy), matching Guid.NewGuid().ToString("N").
    pub fn random_id() -> String {
        let mut bytes = [0u8; 16];
        getrandom::getrandom(&mut bytes).expect("CSPRNG do sistema operacional indisponivel");
        let mut out = String::with_capacity(32);
        for b in bytes {
            use std::fmt::Write;
            let _ = write!(&mut out, "{b:02x}");
        }
        out
    }

    pub fn derive_vault_key(passphrase: &str, master_salt: &[u8]) -> Zeroizing<[u8; KEY_SIZE]> {
        let mut key = Zeroizing::new([0u8; KEY_SIZE]);
        pbkdf2_hmac::<Sha512>(
            passphrase.as_bytes(),
            master_salt,
            KDF_ITERATIONS,
            key.as_mut_slice(),
        );
        key
    }

    pub fn derive_entry_key(
        vault_key: &[u8; KEY_SIZE],
        entry_id: &str,
        entry_salt: &[u8],
    ) -> Zeroizing<[u8; KEY_SIZE]> {
        let mut key = Zeroizing::new([0u8; KEY_SIZE]);
        let hk = Hkdf::<Sha256>::new(Some(entry_salt), vault_key);
        let mut info = Vec::with_capacity(13 + entry_id.len());
        info.extend_from_slice(b"svault:entry:");
        info.extend_from_slice(entry_id.as_bytes());
        hk.expand(&info, key.as_mut_slice())
            .expect("HKDF output length 32 is always valid");
        key
    }

    pub fn seal(plaintext: &[u8], key: &[u8; KEY_SIZE]) -> Vec<u8> {
        let nonce_bytes = Self::random_nonce();
        let cipher = Aes256Gcm::new(key.into());
        let ciphertext_and_tag = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
            .expect("AES-256-GCM encryption failed");

        let mut envelope = Vec::with_capacity(1 + NONCE_SIZE + ciphertext_and_tag.len());
        envelope.push(1u8);
        envelope.extend_from_slice(&nonce_bytes);
        envelope.extend_from_slice(&ciphertext_and_tag);
        envelope
    }

    pub fn try_open(envelope: &[u8], key: &[u8; KEY_SIZE]) -> Option<Zeroizing<Vec<u8>>> {
        if envelope.len() < 1 + NONCE_SIZE + TAG_SIZE || envelope[0] != 1 {
            return None;
        }

        let nonce = Nonce::from_slice(&envelope[1..1 + NONCE_SIZE]);
        let ciphertext_and_tag = &envelope[1 + NONCE_SIZE..];
        let cipher = Aes256Gcm::new(key.into());
        cipher
            .decrypt(nonce, ciphertext_and_tag)
            .ok()
            .map(Zeroizing::new)
    }

    pub fn to_base64(data: &[u8]) -> String {
        BASE64_STANDARD.encode(data)
    }

    pub fn from_base64(data: &str) -> Result<Vec<u8>, String> {
        BASE64_STANDARD
            .decode(data.trim())
            .map_err(|_| "Base64 invalido.".to_owned())
    }

    pub fn fixed_time_equals(a: &[u8], b: &[u8]) -> bool {
        a.len() == b.len() && bool::from(a.ct_eq(b))
    }
}

/// RFC 3986 percent-encoding matching .NET `Uri.EscapeDataString`.
pub fn escape_data_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            use std::fmt::Write;
            let _ = write!(&mut out, "%{byte:02X}");
        }
    }
    out
}

/// RFC 6238 TOTP (SHA-1, 30 second step, 6 digits).
pub struct Totp;

impl Totp {
    pub const DEFAULT_STEP_SECONDS: i64 = 30;
    pub const DEFAULT_DIGITS: u32 = 6;

    pub fn generate_secret(length_bytes: usize) -> String {
        let bytes = Zeroizing::new(VaultCrypto::random_bytes(length_bytes));
        Base32::encode(&bytes)
    }

    pub fn generate_secret_default() -> String {
        Self::generate_secret(20)
    }

    pub fn generate_code(base32_secret: &str, utc_now: DateTime<Utc>) -> Result<String, String> {
        Self::generate_code_with(
            base32_secret,
            utc_now,
            Self::DEFAULT_STEP_SECONDS,
            Self::DEFAULT_DIGITS,
        )
    }

    pub fn generate_code_with(
        base32_secret: &str,
        utc_now: DateTime<Utc>,
        step_seconds: i64,
        digits: u32,
    ) -> Result<String, String> {
        let key = Base32::decode(base32_secret)?;
        let counter = utc_now.timestamp() / step_seconds;
        Ok(Self::compute_hotp(&key, counter, digits))
    }

    pub fn verify_code(base32_secret: &str, code: &str, utc_now: DateTime<Utc>) -> bool {
        Self::verify_code_with(
            base32_secret,
            code,
            utc_now,
            1,
            Self::DEFAULT_STEP_SECONDS,
            Self::DEFAULT_DIGITS,
        )
    }

    pub fn verify_code_with(
        base32_secret: &str,
        code: &str,
        utc_now: DateTime<Utc>,
        window: i64,
        step_seconds: i64,
        digits: u32,
    ) -> bool {
        if code.trim().is_empty() {
            return false;
        }

        let normalized: String = code
            .trim()
            .chars()
            .filter(|c| *c != ' ' && *c != '-')
            .collect();
        if normalized.len() != digits as usize || !normalized.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }

        let Ok(key) = Base32::decode(base32_secret) else {
            return false;
        };
        let counter = utc_now.timestamp() / step_seconds;

        for drift in -window..=window {
            let candidate = Self::compute_hotp(&key, counter + drift, digits);
            if VaultCrypto::fixed_time_equals(candidate.as_bytes(), normalized.as_bytes()) {
                return true;
            }
        }

        false
    }

    pub fn build_otp_auth_uri(secret: &str, account: &str, issuer: &str) -> String {
        let label = escape_data_string(&format!("{issuer}:{account}"));
        let issuer_enc = escape_data_string(issuer);
        format!(
            "otpauth://totp/{label}?secret={secret}&issuer={issuer_enc}&algorithm=SHA1&digits=6&period=30"
        )
    }

    fn compute_hotp(key: &[u8], counter: i64, digits: u32) -> String {
        let buffer = (counter as u64).to_be_bytes();
        let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("HMAC accepts any key size");
        mac.update(&buffer);
        let hash = mac.finalize().into_bytes();

        let offset = (hash[hash.len() - 1] & 0x0F) as usize;
        let binary = (((hash[offset] & 0x7F) as u32) << 24)
            | ((hash[offset + 1] as u32) << 16)
            | ((hash[offset + 2] as u32) << 8)
            | (hash[offset + 3] as u32);

        let modulo = 10u32.pow(digits);
        format!("{:0width$}", binary % modulo, width = digits as usize)
    }
}

pub struct Base32;

impl Base32 {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    pub fn encode(data: &[u8]) -> String {
        let mut builder = String::with_capacity((data.len() * 8 / 5) + 1);
        let mut buffer: u32 = 0;
        let mut bits_left: u32 = 0;

        for &b in data {
            buffer = (buffer << 8) | (b as u32);
            bits_left += 8;
            while bits_left >= 5 {
                let idx = ((buffer >> (bits_left - 5)) & 0x1F) as usize;
                builder.push(Self::ALPHABET[idx] as char);
                bits_left -= 5;
            }
        }

        if bits_left > 0 {
            let idx = ((buffer << (5 - bits_left)) & 0x1F) as usize;
            builder.push(Self::ALPHABET[idx] as char);
        }

        builder
    }

    pub fn decode(encoded: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        let cleaned: String = encoded
            .chars()
            .filter(|c| *c != ' ' && *c != '-')
            .collect::<String>()
            .trim_end_matches('=')
            .to_owned();

        let mut bytes = Zeroizing::new(Vec::with_capacity(cleaned.len() * 5 / 8));
        let mut buffer: u32 = 0;
        let mut bits_left: u32 = 0;

        for ch in cleaned.chars() {
            let upper = ch.to_ascii_uppercase();
            let Some(index) = Self::ALPHABET.iter().position(|&b| b == upper as u8) else {
                return Err("Invalid base32 character.".to_owned());
            };

            buffer = (buffer << 5) | (index as u32);
            bits_left += 5;
            if bits_left >= 8 {
                bytes.push(((buffer >> (bits_left - 8)) & 0xFF) as u8);
                bits_left -= 8;
            }
        }

        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn seal_and_open_round_trip_matches_envelope_layout() {
        let salt = VaultCrypto::random_salt();
        let vk = VaultCrypto::derive_vault_key("senha-de-teste-123", &salt);
        let ek = VaultCrypto::derive_entry_key(&vk, "CPF_PESSOAL", &salt);
        let env = VaultCrypto::seal(b"529.982.247-25", &ek);
        assert_eq!(env[0], 1u8);
        assert_eq!(env.len(), 1 + NONCE_SIZE + 14 + TAG_SIZE);

        let opened = VaultCrypto::try_open(&env, &ek).expect("should open");
        assert_eq!(&opened[..], b"529.982.247-25");

        let wrong_key = [0u8; KEY_SIZE];
        assert!(VaultCrypto::try_open(&env, &wrong_key).is_none());
    }

    #[test]
    fn rfc6238_totp_vectors_and_drift_window() {
        // "12345678901234567890" in Base32 is GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let t59 = Utc.timestamp_opt(59, 0).unwrap();
        let code = Totp::generate_code(secret, t59).unwrap();
        assert_eq!(code, "287082");
        assert!(Totp::verify_code(secret, "287 082", t59));
        let t89 = Utc.timestamp_opt(89, 0).unwrap();
        assert!(Totp::verify_code(secret, "287082", t89));
        assert!(!Totp::verify_code(secret, "000000", t59));
    }

    #[test]
    fn base32_round_trip() {
        let raw = b"svault-secret-bytes!";
        let encoded = Base32::encode(raw);
        let decoded = Base32::decode(&encoded).unwrap();
        assert_eq!(&decoded[..], raw);
        assert!(Base32::decode("INVALID!@#").is_err());
    }
}
