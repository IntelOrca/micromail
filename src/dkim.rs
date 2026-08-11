use crate::error::{Error, Result};
use mail_send::mail_auth::common::crypto::{DkimKey, Ed25519Key, RsaKey, Sha256};
use mail_send::mail_auth::dkim::{DkimSigner, Done};
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject};
use std::collections::HashMap;
use std::path::Path;

/// Headers eligible for DKIM signing, in priority order.
pub const DKIM_HEADERS: &[&str] = &[
    "From",
    "To",
    "Cc",
    "Subject",
    "Date",
    "Message-ID",
    "Reply-To",
    "MIME-Version",
    "Content-Type",
    "Content-Transfer-Encoding",
];

pub struct DkimEntry {
    pub domain: String,
    pub selector: String,
    key_pem: Vec<u8>,
}

/// Holds the DKIM keys discovered under `<config dir>/dkim/<domain>/`.
pub struct DkimManager {
    entries: HashMap<String, DkimEntry>,
    default_selector: String,
}

impl DkimManager {
    /// Scan `dkim_dir` (e.g. `/etc/micromail/dkim`) for per-domain subfolders.
    pub fn load(dkim_dir: &Path, default_selector: &str) -> Result<Self> {
        let mut entries = HashMap::new();

        if dkim_dir.is_dir() {
            for sub in std::fs::read_dir(dkim_dir)? {
                let sub = sub?;
                if !sub.file_type()?.is_dir() {
                    continue;
                }
                let domain = sub.file_name().to_string_lossy().to_lowercase();
                if domain.is_empty() || domain.starts_with('.') {
                    continue;
                }
                let dir = sub.path();
                let Some(key_path) = find_key_file(&dir) else {
                    continue;
                };
                let key_pem = std::fs::read(&key_path)?;
                let selector = read_selector(&dir, default_selector);
                // Validate the key parses before accepting the domain.
                parse_key(&key_pem)?;
                entries.insert(
                    domain.clone(),
                    DkimEntry {
                        domain,
                        selector,
                        key_pem,
                    },
                );
            }
        }

        Ok(DkimManager {
            entries,
            default_selector: default_selector.to_string(),
        })
    }

    /// Number of domains with DKIM keys.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// True when a signing key exists for `domain`.
    pub fn has_signer(&self, domain: &str) -> bool {
        self.entries.contains_key(domain)
    }

    /// Build a ready-to-use DKIM signer for `domain`, signing the given
    /// `headers` (they should be a subset of the headers present in the
    /// message being signed).
    pub fn build_signer(&self, domain: &str, headers: &[&str]) -> Result<DkimSigner<DkimKey, Done>> {
        let entry = self
            .entries
            .get(domain)
            .ok_or_else(|| Error::Dkim(format!("no DKIM key for domain {domain}")))?;
        let key = parse_key(&entry.key_pem)?;
        Ok(DkimSigner::from_key(key)
            .domain(entry.domain.clone())
            .selector(entry.selector.clone())
            .headers(headers.iter().map(|h| (*h).to_string())))
    }

    pub fn default_selector(&self) -> &str {
        &self.default_selector
    }
}

fn find_key_file(dir: &Path) -> Option<std::path::PathBuf> {
    const NAMES: &[&str] = &["dkim.pem", "private.pem", "key.pem", "dkim.private.pem", "dkim.key"];
    for name in NAMES {
        let path = dir.join(name);
        if path.is_file() {
            return Some(path);
        }
    }
    // Fall back to the first *.pem file in the directory.
    let Ok(files) = std::fs::read_dir(dir) else {
        return None;
    };
    let mut pem_files: Vec<std::path::PathBuf> = files
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_type().map(|t| t.is_file()).unwrap_or(false)
                && e.file_name().to_string_lossy().ends_with(".pem")
        })
        .map(|e| e.path())
        .collect();
    pem_files.sort();
    pem_files.into_iter().next()
}

fn read_selector(dir: &Path, default_selector: &str) -> String {
    match std::fs::read_to_string(dir.join("selector")) {
        Ok(value) => {
            let value = value.trim().to_string();
            if value.is_empty() {
                default_selector.to_string()
            } else {
                value
            }
        }
        Err(_) => default_selector.to_string(),
    }
}

/// Parse a PEM private key into a DKIM signing key, accepting RSA (PKCS1 or
/// PKCS8) and Ed25519 (PKCS8).
fn parse_key(pem: &[u8]) -> Result<DkimKey> {
    let der = PrivateKeyDer::from_pem_slice(pem)
        .map_err(|e| Error::Dkim(format!("cannot parse private key PEM: {e}")))?;
    match der {
        PrivateKeyDer::Pkcs1(d) => Ok(DkimKey::Rsa(
            RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs1(d))?,
        )),
        PrivateKeyDer::Pkcs8(d) => {
            let bytes = d.secret_pkcs8_der().to_vec();
            match RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs8(
                PrivatePkcs8KeyDer::from(&bytes[..]),
            )) {
                Ok(key) => Ok(DkimKey::Rsa(key)),
                Err(_) => Ok(DkimKey::Ed25519(Ed25519Key::from_pkcs8_der(&bytes)?)),
            }
        }
        _ => Err(Error::Dkim(
            "unsupported private key format for DKIM; use RSA or Ed25519".into(),
        )),
    }
}

/// Compute the list of headers to sign for a message: the intersection of the
/// headers actually present in `raw_message` with the preferred list.
pub fn headers_to_sign(raw_message: &[u8]) -> Vec<&'static str> {
    use std::collections::HashSet;

    let present: HashSet<String> = mail_parser::MessageParser::default()
        .parse(raw_message)
        .map(|m| {
            m.headers()
                .iter()
                .map(|h| h.name().to_ascii_lowercase())
                .collect()
        })
        .unwrap_or_default();

    DKIM_HEADERS
        .iter()
        .copied()
        .filter(|h| present.contains(&h.to_ascii_lowercase()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const RSA_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCtAHJpFBnD/fUk
9MgGiQHSaGumdR/zIRrcqB9IICV0cl156uw7OwjlUvQ1YkFRVIchZBiLpkx2nXJt
eBmRmcJb9M5hLGonLRKFj77/fFRUO/ZAh+ohpVU/UoG6G1Uwb9JcaOoe/HOFuCnB
U4VmJ/9qtlmDTNmqz3TD23hFVYAz14eBs44SxRcubt0Lv1mqripWU2M8q55TC4Ic
k67/zD0RNRkntNv49Xug6l+GxJZe0pxwPRKDxc5gYJYa8/JG2uFwT9reO5HokOTL
0cyHeBV2R1eeoS+mZCS7TpRmY0V5RlrMuOf6QUx5Nl9Ev7gcfsEHj8Zv9zFIweLD
R15jiAPpAgMBAAECggEACKsAMIDd8h6aLuf3UjGA5n2OIDzX1RcUaRgg2hynN8SH
p7VEMQsKDPBpNTgHMQegziTdYHjcdah5nF/DOzL2pKQZR4/hwTT+S7QaNCOS95X6
Bn1w1w75PJcaEhyuueKuaewlR9hrAtkJeYrhYQ8RunNovH4IHWlvzqTjS6kHJ4G4
yFPd5+Ys/HdPZYI4ojDFNSZHDYJY9TdEV5JmYvENB8aQLoa1YENWTgFvARfwRKlH
se4gwDgPiN3vXPtazGsKvWNw05SM2fa8sDExA22oQJx9A7Vtp/D+lkH2WM4mQlBy
Ee+uVjB/8RkBpK0+choSoHRygYUwZh+gmla3gjm/AQKBgQDbcSpG5tis5GWFyu1U
tbgBLq7FapjBA05e/vY0pveArNMDMjVAhMiHHV4KPNr468tsNYggnNxX0cR+gYkx
yyJ1/z/ty0IW5RZxh9vrlXNLZKLx0plXdJydFT9aTlurqmNx7JCFZNqGy3Wu+gg4
fRZZopAC7dVTQc5JUC4fXqzHAQKBgQDJ0q5FxtktVzLlWC41dN3iIxzULVsv6G45
iGK1BDeavExWaFiQufb68ESY11nX3+Eu3jpLrZrJ7xm//spXaEp4aIpb/mlpMrKA
1iPXU8BD/cMu3eD4oJdvOgnW4BUBX+QAG6ImsuxNWvXendptDOUnzdpfunvroHK6
opUIkQrk6QKBgEng34rfTTNn8YYJu705MKm1PcHZEXRp2IjC7cDsNYdsp937mVIP
YjOa/34S3uXO/L2BiELyjHxEcxLkKXxKF2ACf1NfivCKT/QI+VFnD1nil7kyXc3D
xLZd4OZWWyaARtqj+kPuoGOhPA2cwAfElTG4OSPDTn6pOPoVtHF7PlABAoGAM/0T
a2IHu8hEkhOfA6IxLfmBiZ6NaM/k5OkfFCYb9L4go/mJJu7gkk+mPADtYdCH/zy7
o5b60p3G8lA96zowRMgZLA1jNfgbR1jiLquiUWFjEAWT2Df2Cm7W7gUXJB2BbA2y
PWnFuT9/KnNbOtAhj5lVcWdmWJIiO7V50pUaS1ECgYEAndhsJ9k+2ft5mQBkv7Ve
WYfzaEq7EvsnNGbiV7ToPgNT9weE5Az1Tlhak7HMUo5xsh0oR3gF3GIyeSMYBmG/
4gHZuhUx0balp7fdbnz5l+1SvIylCxjeGRzUi/A0VTSMi3bKmNBxsWWg/RRbWZnI
ccRqGWFXwwPUPeTFHVTFnLE=
-----END PRIVATE KEY-----"#;

    fn key_dir() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let domain_dir = dir.path().join("dkim/example.com");
        std::fs::create_dir_all(&domain_dir).unwrap();
        std::fs::write(domain_dir.join("dkim.pem"), RSA_KEY).unwrap();
        std::fs::write(domain_dir.join("selector"), "mail2026\n").unwrap();
        let dkim_root = dir.path().join("dkim");
        (dir, dkim_root)
    }

    #[test]
    fn loads_per_domain_keys() {
        let (dir, dkim) = key_dir();
        let manager = DkimManager::load(&dkim, "default").unwrap();
        assert_eq!(manager.len(), 1);
        assert!(manager.has_signer("example.com"));
        assert!(!manager.has_signer("other.com"));
        drop(dir);
    }

    #[test]
    fn selector_falls_back_to_default() {
        let dir = tempfile::tempdir().unwrap();
        let domain_dir = dir.path().join("dkim/example.org");
        std::fs::create_dir_all(&domain_dir).unwrap();
        std::fs::write(domain_dir.join("private.pem"), RSA_KEY).unwrap();
        let manager = DkimManager::load(&dir.path().join("dkim"), "fallback").unwrap();
        assert!(manager.has_signer("example.org"));
        drop(dir);
    }

    #[test]
    fn parses_rsa_key() {
        let key = parse_key(RSA_KEY.as_bytes()).unwrap();
        assert!(matches!(key, DkimKey::Rsa(_)));
    }

    #[test]
    fn builds_signer() {
        let (dir, dkim) = key_dir();
        let manager = DkimManager::load(&dkim, "default").unwrap();
        let signer = manager.build_signer("example.com", &["From", "To", "Subject"]);
        assert!(signer.is_ok());
        drop(dir);
    }

    #[test]
    fn computes_signing_headers() {
        let raw = b"From: a@example.com\r\nTo: b@example.com\r\nSubject: Hi\r\n\r\nbody\r\n";
        let headers = headers_to_sign(raw);
        assert!(headers.contains(&"From"));
        assert!(headers.contains(&"To"));
        assert!(headers.contains(&"Subject"));
        assert!(!headers.contains(&"Message-ID"));
    }
}
