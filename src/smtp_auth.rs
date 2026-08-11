use crate::config::SmtpUser;
use base64::{Engine, engine::general_purpose::STANDARD};

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

/// Check credentials against the configured users.
pub fn authenticate(users: &[SmtpUser], username: &str, password: &str) -> bool {
    users
        .iter()
        .any(|u| constant_time_eq(u.username.as_bytes(), username.as_bytes())
            && constant_time_eq(u.password.as_bytes(), password.as_bytes()))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
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
    use base64::{Engine, engine::general_purpose::STANDARD};

    fn plain(user: &str, pass: &str) -> String {
        STANDARD.encode(format!("\0{user}\0{pass}"))
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
        let users = vec![SmtpUser {
            username: "app".into(),
            password: "hunter2".into(),
        }];
        assert!(authenticate(&users, "app", "hunter2"));
        assert!(!authenticate(&users, "app", "wrong"));
        assert!(!authenticate(&users, "nobody", "hunter2"));
        assert!(!authenticate(&users, "app", ""));
    }
}
