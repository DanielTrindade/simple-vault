use std::collections::HashSet;

use serde_json::{Map, Value};

use crate::crypto::{VaultCrypto, escape_data_string};

pub const MASK: &str = "***REDACTED***";
pub const MAX_OUTPUT_LENGTH: usize = 8_192;

/// Removes a secret from any text that may reach the agent, a log file or an error message.
/// Works on the textual projections of the secret that are likely to show up in payloads:
/// raw value, url encoded, base64 and digit-only (for CPF style identifiers).
#[derive(Debug, Clone)]
pub struct SecretRedactor {
    variants: Vec<String>,
}

impl SecretRedactor {
    pub fn from_single(secret: &[u8]) -> Self {
        Self::new([secret])
    }

    pub fn new<'a, I>(secrets: I) -> Self
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let mut set = HashSet::new();

        for secret in secrets {
            let raw = String::from_utf8_lossy(secret).into_owned();
            Self::add(&mut set, &raw);

            let digits: String = raw.chars().filter(|c| c.is_ascii_digit()).collect();
            if digits.len() >= 8 && digits.len() != raw.len() {
                Self::add(&mut set, &digits);
            }

            let formatted: String = raw
                .chars()
                .filter(|c| c.is_ascii_digit() || matches!(c, '.' | '-' | '/'))
                .collect();
            if formatted.len() >= 8 {
                Self::add(&mut set, &formatted);
            }

            Self::add(&mut set, &escape_data_string(&raw));
            Self::add(&mut set, &VaultCrypto::to_base64(secret));
            Self::add(&mut set, &raw.to_uppercase());
            Self::add(&mut set, &raw.to_lowercase());
        }

        let mut variants: Vec<String> = set.into_iter().collect();
        variants.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        Self { variants }
    }

    fn add(set: &mut HashSet<String>, value: &str) {
        if !value.is_empty() {
            set.insert(value.to_owned());
        }
    }

    pub fn redact(&self, text: &str) -> String {
        if text.is_empty() {
            return String::new();
        }

        if let Ok(parsed) = serde_json::from_str::<Value>(text)
            && !parsed.is_null()
        {
            let redacted = self.redact_node(parsed);
            if let Ok(serialized) = serde_json::to_string(&redacted) {
                return Self::truncate(&serialized);
            }
        }

        Self::truncate(&self.redact_text(text))
    }

    pub fn redact_nullable(&self, text: Option<&str>) -> Option<String> {
        text.map(|t| self.redact(t))
    }

    fn redact_node(&self, node: Value) -> Value {
        match node {
            Value::Object(obj) => {
                let mut next = Map::with_capacity(obj.len());
                for (key, value) in obj {
                    let redacted_key = self.redact_text(&key);
                    let redacted_value = self.redact_node(value);
                    next.insert(redacted_key, redacted_value);
                }
                Value::Object(next)
            }
            Value::Array(arr) => Value::Array(
                arr.into_iter()
                    .map(|elem| self.redact_node(elem))
                    .collect(),
            ),
            Value::String(s) => Value::String(self.redact_text(&s)),
            Value::Bool(b) => {
                let raw = if b { "true" } else { "false" };
                let redacted = self.redact_text(raw);
                if redacted == raw {
                    Value::Bool(b)
                } else {
                    Value::String(redacted)
                }
            }
            Value::Number(n) => {
                let raw = n.to_string();
                let redacted = self.redact_text(&raw);
                if redacted == raw {
                    Value::Number(n)
                } else {
                    Value::String(redacted)
                }
            }
            Value::Null => Value::Null,
        }
    }

    fn redact_text(&self, text: &str) -> String {
        if self.variants.is_empty() || text.is_empty() {
            return text.to_owned();
        }

        let mut builder = String::with_capacity(text.len());
        let mut index = 0;
        while index < text.len() {
            let tail = &text[index..];
            let matched = self
                .variants
                .iter()
                .find(|variant| tail.starts_with(variant.as_str()));

            if tail.starts_with(MASK) && matched.is_none_or(|m| m.len() < MASK.len()) {
                builder.push_str(MASK);
                index += MASK.len();
                continue;
            }

            if let Some(m) = matched {
                builder.push_str(MASK);
                index += m.len();
                continue;
            }

            let ch = tail.chars().next().expect("non-empty tail");
            builder.push(ch);
            index += ch.len_utf8();
        }

        builder
    }

    pub fn truncate(text: &str) -> String {
        if text.chars().count() <= MAX_OUTPUT_LENGTH {
            return text.to_owned();
        }

        let prefix: String = text.chars().take(MAX_OUTPUT_LENGTH).collect();
        format!("{prefix}\n...[truncated]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_escaped_json_short_secrets_markers_and_booleans() {
        let redactor = SecretRedactor::from_single(b"fake&value");
        let json = redactor.redact(r#"{"echo":"fake\u0026value"}"#);
        assert!(!json.contains("fake"));

        let short = SecretRedactor::from_single(b"R");
        let once = short.redact("secret=R");
        assert_eq!(once, "sec***REDACTED***et=***REDACTED***");
        assert_eq!(once, short.redact(&once));

        let marker = SecretRedactor::from_single(b"***REDACTED***suffix-privado");
        assert!(!marker.redact("prefix=***REDACTED***suffix-privado").contains("suffix-privado"));

        let boolean = SecretRedactor::from_single(b"false");
        assert!(boolean.redact(r#"{"value":false}"#).contains(MASK));
    }

    #[test]
    fn redacts_cpf_digit_variants() {
        let redactor = SecretRedactor::from_single(b"529.982.247-25");
        assert!(!redactor.redact("cpf=52998224725").contains("52998224725"));
        assert!(!redactor.redact("cpf=529.982.247-25").contains("529.982"));
    }
}
