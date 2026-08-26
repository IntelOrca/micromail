use crate::error::{Error, Result};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

const PREFIX_LITERAL: &str = "literal:";
const PREFIX_ARGON2: &str = "argon2:";

/// Number of random bytes behind a generated API token.
const GENERATED_TOKEN_BYTES: usize = 32;

/// Hash a plaintext secret with Argon2id (default parameters, random salt)
/// and return the PHC-formatted hash string for storage as `argon2:<PHC>`.
pub fn hash(plain: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(plain.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| Error::Config(format!("failed to hash secret: {e}")))
}

/// Build the config value for a hashed secret: `argon2:<PHC string>`.
pub fn argon2_value(plain: &str) -> Result<String> {
    Ok(format!("{PREFIX_ARGON2}{}", hash(plain)?))
}

/// Build the config value for a literal secret: `literal:<plaintext>`.
pub fn literal_value(plain: &str) -> String {
    format!("{PREFIX_LITERAL}{plain}")
}

/// Generate a cryptographically random, URL-safe bearer token
/// (43 characters from 32 bytes of OS entropy).
pub fn generate_token() -> String {
    let mut bytes = [0u8; GENERATED_TOKEN_BYTES];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// A configured credential with an explicit storage scheme prefix.
///
/// Config values must be either `literal:<plaintext>` (plaintext secret,
/// compared in constant time) or `argon2:<PHC hash>` (an Argon2 PHC string
/// such as `$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`, verified with
/// Argon2id using the parameters embedded in the hash).
#[derive(Clone, PartialEq, Eq)]
pub enum Secret {
    Literal(String),
    Argon2(String),
}

impl Secret {
    /// Parse a prefixed credential string. Unprefixed values are rejected.
    pub fn parse(raw: &str) -> Result<Secret> {
        if let Some(value) = raw.strip_prefix(PREFIX_ARGON2) {
            if value.is_empty() {
                return Err(Error::Config(
                    "empty credential after \"argon2:\" prefix".into(),
                ));
            }
            Ok(Secret::Argon2(value.to_string()))
        } else if let Some(value) = raw.strip_prefix(PREFIX_LITERAL) {
            if value.is_empty() {
                return Err(Error::Config(
                    "empty credential after \"literal:\" prefix".into(),
                ));
            }
            Ok(Secret::Literal(value.to_string()))
        } else {
            Err(Error::Config(
                "credential has no storage scheme; \
                 prefix it with \"literal:\" or \"argon2:\""
                    .into(),
            ))
        }
    }

    /// Check a candidate plaintext against this secret.
    pub fn verify(&self, candidate: &str) -> bool {
        match self {
            Secret::Literal(expected) => {
                constant_time_eq(expected.as_bytes(), candidate.as_bytes())
            }
            Secret::Argon2(hash) => PasswordHash::new(hash)
                .and_then(|parsed| Argon2::default().verify_password(candidate.as_bytes(), &parsed))
                .is_ok(),
        }
    }

    /// The plaintext payload when this is a literal secret. `None` for
    /// Argon2 hashes, which cannot be reversed.
    pub fn literal(&self) -> Option<&str> {
        match self {
            Secret::Literal(value) => Some(value),
            Secret::Argon2(_) => None,
        }
    }

    /// The storage scheme of this secret: `"literal"` or `"argon2"`.
    pub fn scheme(&self) -> &'static str {
        match self {
            Secret::Literal(_) => "literal",
            Secret::Argon2(_) => "argon2",
        }
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Secret::Literal(_) => write!(f, "Secret::Literal(**redacted**)"),
            Secret::Argon2(_) => write!(f, "Secret::Argon2(**redacted**)"),
        }
    }
}

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Secret::Literal(value) => serializer.serialize_str(&format!("{PREFIX_LITERAL}{value}")),
            Secret::Argon2(value) => serializer.serialize_str(&format!("{PREFIX_ARGON2}{value}")),
        }
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct SecretVisitor;

        impl Visitor<'_> for SecretVisitor {
            type Value = Secret;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    f,
                    "a credential string prefixed with \"{PREFIX_LITERAL}\" or \"{PREFIX_ARGON2}\""
                )
            }

            fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Secret, E> {
                Secret::parse(value).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_str(SecretVisitor)
    }
}

/// Byte-wise constant-time equality for secret comparisons.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::password_hash::{PasswordHasher, SaltString};
    use argon2::{Algorithm, Params, Version};

    const TEST_SALT: &str = "c3RhdGljIHNhbHQgMTIzNDU2";

    /// Hash with deliberately weak parameters so tests stay fast.
    fn fast_phc_hash(password: &str) -> String {
        let salt = SaltString::from_b64(TEST_SALT).expect("valid static test salt");
        let params = Params::new(1024, 1, 1, Some(32)).expect("valid static test params");
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        argon
            .hash_password(password.as_bytes(), &salt)
            .expect("test password hashes")
            .to_string()
    }

    #[test]
    fn parses_literal() {
        let secret = Secret::parse("literal:hunter2").unwrap();
        assert_eq!(secret, Secret::Literal("hunter2".into()));
    }

    #[test]
    fn parses_literal_containing_colons() {
        let secret = Secret::parse("literal:pa:ss:word").unwrap();
        assert_eq!(secret, Secret::Literal("pa:ss:word".into()));
    }

    #[test]
    fn parses_argon2() {
        let raw = "argon2:$argon2id$v=19$m=1024,t=1,p=1$salt$hash";
        let secret = Secret::parse(raw).unwrap();
        assert_eq!(
            secret,
            Secret::Argon2("$argon2id$v=19$m=1024,t=1,p=1$salt$hash".into())
        );
    }

    #[test]
    fn rejects_missing_prefix() {
        let err = Secret::parse("hunter2").unwrap_err().to_string();
        assert!(err.contains("literal:"), "unexpected error: {err}");
        assert!(err.contains("argon2:"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_unknown_prefix() {
        assert!(Secret::parse("bcrypt:hunter2").is_err());
        assert!(Secret::parse(":hunter2").is_err());
    }

    #[test]
    fn rejects_empty_value() {
        assert!(Secret::parse("literal:").is_err());
        assert!(Secret::parse("argon2:").is_err());
        assert!(Secret::parse("").is_err());
    }

    #[test]
    fn verifies_literal() {
        let secret = Secret::parse("literal:hunter2").unwrap();
        assert!(secret.verify("hunter2"));
        assert!(!secret.verify("Hunter2"));
        assert!(!secret.verify(""));
    }

    #[test]
    fn verifies_argon2() {
        let secret = Secret::Argon2(fast_phc_hash("hunter2"));
        assert!(secret.verify("hunter2"));
        assert!(!secret.verify("wrong"));
        assert!(!secret.verify(""));
    }

    #[test]
    fn corrupt_argon2_never_verifies() {
        let secret = Secret::Argon2("not-a-phc-string".into());
        assert!(!secret.verify("anything"));
    }

    #[test]
    fn literal_extraction() {
        assert_eq!(Secret::parse("literal:p").unwrap().literal(), Some("p"));
        assert_eq!(Secret::Argon2("$h".into()).literal(), None);
    }

    #[test]
    fn debug_output_is_redacted() {
        let literal = Secret::parse("literal:hunter2").unwrap();
        let rendered = format!("{literal:?}");
        assert!(
            !rendered.contains("hunter2"),
            "leaked via Debug: {rendered}"
        );
        assert!(rendered.contains("redacted"));

        let argon2 = Secret::parse("argon2:$argon2id$v=19$m=1024,t=1,p=1$s$abc").unwrap();
        assert!(!format!("{argon2:?}").contains("$argon2id"));
    }

    #[test]
    fn round_trips_through_toml() {
        let literal = Secret::parse("literal:hunter2").unwrap();
        let encoded = toml::Value::try_from(&literal).unwrap();
        assert_eq!(encoded.as_str(), Some("literal:hunter2"));
        let decoded: Secret = encoded.try_into().unwrap();
        assert_eq!(decoded, literal);
    }

    #[test]
    fn hash_produces_verifiable_argon2() {
        let raw = hash("hunter2").unwrap();
        assert!(raw.starts_with("$argon2id$"), "{raw}");
        let secret = Secret::parse(&format!("argon2:{raw}")).unwrap();
        assert_eq!(secret.scheme(), "argon2");
        assert!(secret.verify("hunter2"));
        assert!(!secret.verify("wrong"));
        // A fresh salt must be used each time.
        assert_ne!(hash("hunter2").unwrap(), raw);
    }

    #[test]
    fn hash_is_unique_per_call() {
        let a = hash("same").unwrap();
        let b = hash("same").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn prefixed_value_builders() {
        assert_eq!(literal_value("pa:ss"), "literal:pa:ss");
        let hashed = argon2_value("hunter2").unwrap();
        assert!(hashed.starts_with("argon2:$argon2id$"), "{hashed}");
    }

    #[test]
    fn generated_tokens_are_url_safe_and_unique() {
        let first = generate_token();
        let second = generate_token();
        assert_eq!(first.len(), 43);
        assert_ne!(first, second);
        for token in [&first, &second] {
            assert!(
                token
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
                "{token}"
            );
        }
    }
}
