use crate::config::SmtpUser;
use base64::{engine::general_purpose::STANDARD, Engine};

/// Decode an AUTH PLAIN initial response of the form
/// `<authzid>\0<authcid>\0<password>`.
pub fn decode_plain(b64: &str) -> Result<(String, String), String> {
    let decoded = STANDARD
        .decode(b64.trim())
        .map_err(|e| format!("invalid base64: {e}"))?;
    let mut parts = decoded.split(|b| *b == 0);
    let _authzid = parts.next();
    let user = parts
        .next()
        .and_then(|b| std::str::from_utf8(b).ok())
        .ok_or_else(|| "malformed AUTH PLAIN response".to_string())?;
    let pass = parts
        .next()
        .and_then(|b| std::str::from_utf8(b).ok())
        .ok_or_else(|| "malformed AUTH PLAIN response".to_string())?;
    if user.is_empty() {
        return Err("empty username".to_string());
    }
    Ok((user.to_string(), pass.to_string()))
}

/// Decode a base64 challenge response (used by AUTH LOGIN).
pub fn decode_b64(s: &str) -> Result<String, String> {
    let bytes = STANDARD
        .decode(s.trim())
        .map_err(|e| format!("invalid base64: {e}"))?;
    String::from_utf8(bytes).map_err(|_| "not valid UTF-8".to_string())
}

/// Base64-encode a challenge prompt (AUTH LOGIN username/password requests).
pub fn encode_challenge(label: &str) -> String {
    STANDARD.encode(label.as_bytes())
}

/// Check credentials against the configured users. Usernames are matched
/// ASCII case-insensitively; passwords are verified exactly.
pub fn authenticate(users: &[SmtpUser], username: &str, password: &str) -> bool {
    users
        .iter()
        .any(|u| u.username.eq_ignore_ascii_case(username) && u.password.verify(password))
}

/// [`authenticate`] off the async worker threads. Argon2 verification is
/// CPU- and memory-heavy; running it inline would stall other connections.
pub async fn authenticate_async(users: &[SmtpUser], username: &str, password: &str) -> bool {
    let users = users.to_vec();
    let username = username.to_string();
    let password = password.to_string();
    tokio::task::spawn_blocking(move || authenticate(&users, &username, &password))
        .await
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::Secret;
    use argon2::password_hash::{PasswordHasher, SaltString};
    use argon2::{Algorithm, Argon2, Params, Version};
    use base64::{engine::general_purpose::STANDARD, Engine};

    fn plain(user: &str, pass: &str) -> String {
        STANDARD.encode(format!("\0{user}\0{pass}"))
    }

    fn literal_user(username: &str, password: &str) -> SmtpUser {
        SmtpUser {
            username: username.into(),
            password: Secret::Literal(password.into()),
        }
    }

    /// Hash with deliberately weak parameters so tests stay fast.
    fn fast_phc_hash(password: &str) -> String {
        let salt =
            SaltString::from_b64("c3RhdGljIHNhbHQgMTIzNDU2").expect("valid static test salt");
        let params = Params::new(1024, 1, 1, Some(32)).expect("valid static test params");
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        argon
            .hash_password(password.as_bytes(), &salt)
            .expect("test password hashes")
            .to_string()
    }

    #[test]
    fn decodes_plain() {
        let (user, pass) = decode_plain(&plain("alice", "s3cret")).unwrap();
        assert_eq!(user, "alice");
        assert_eq!(pass, "s3cret");
    }

    #[test]
    fn decodes_plain_with_authzid() {
        let token = STANDARD.encode("authz\0alice\0s3cret".as_bytes());
        let (user, pass) = decode_plain(&token).unwrap();
        assert_eq!(user, "alice");
        assert_eq!(pass, "s3cret");
    }

    #[test]
    fn rejects_malformed_plain() {
        assert!(decode_plain("!!!").is_err());
        assert!(decode_plain(&STANDARD.encode("alice".as_bytes())).is_err());
    }

    #[test]
    fn login_challenges_roundtrip() {
        assert_eq!(encode_challenge("Username:"), "VXNlcm5hbWU6");
        assert_eq!(encode_challenge("Password:"), "UGFzc3dvcmQ6");
        assert_eq!(decode_b64("QWxpY2U=").unwrap(), "Alice");
    }

    #[test]
    fn authenticates_users() {
        let users = vec![literal_user("app", "hunter2")];
        assert!(authenticate(&users, "app", "hunter2"));
        assert!(!authenticate(&users, "app", "wrong"));
        assert!(!authenticate(&users, "nobody", "hunter2"));
        assert!(!authenticate(&users, "app", ""));
    }

    #[test]
    fn usernames_are_case_insensitive() {
        let users = vec![literal_user("App", "hunter2")];
        assert!(authenticate(&users, "APP", "hunter2"));
        assert!(authenticate(&users, "app", "hunter2"));
        assert!(authenticate(&users, "aPp", "hunter2"));
        assert!(!authenticate(&users, "application", "hunter2"));
    }

    #[test]
    fn authenticates_argon2_password() {
        let users = vec![SmtpUser {
            username: "app".into(),
            password: Secret::Argon2(fast_phc_hash("hunter2")),
        }];
        assert!(authenticate(&users, "app", "hunter2"));
        assert!(!authenticate(&users, "app", "wrong"));
    }
}
