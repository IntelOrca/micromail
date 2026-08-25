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

/// Holds the DKIM keys discovered under `<config dir>/dkim/<domain>/<selector>`.
/// Each selector file's name is the selector and its contents are the PEM private key.
/// Strict: no legacy `key.pem+selector` file, group/other perms `0o077` rejected.
pub struct DkimManager {
    entries: HashMap<String, HashMap<String, DkimEntry>>,
    default_selector: String,
}

impl DkimManager {
    /// Scan `dkim_dir` (e.g. `~/.config/micromail/dkim`) for per-domain subfolders.
    /// New layout: `dkim/<domain>/<selector>` where selector filename contains PEM.
    pub fn load(dkim_dir: &Path, default_selector: &str) -> Result<Self> {
        let mut entries: HashMap<String, HashMap<String, DkimEntry>> = HashMap::new();

        if dkim_dir.is_dir() {
            Self::load_dir_into(dkim_dir, &mut entries)?;
        }

        Ok(DkimManager {
            entries,
            default_selector: default_selector.to_string(),
        })
    }

    /// Merged load: system dir as base, user dir overlay (user wins on (domain,selector)).
    pub fn load_merged(
        system_dkim_dir: &Path,
        user_dkim_dir: &Path,
        default_selector: &str,
    ) -> Result<Self> {
        let mut entries: HashMap<String, HashMap<String, DkimEntry>> = HashMap::new();
        if system_dkim_dir.is_dir() {
            Self::load_dir_into(system_dkim_dir, &mut entries)?;
        }
        if user_dkim_dir.is_dir() && user_dkim_dir != system_dkim_dir {
            Self::load_dir_into(user_dkim_dir, &mut entries)?;
        }
        Ok(DkimManager {
            entries,
            default_selector: default_selector.to_string(),
        })
    }

    fn load_dir_into(
        dkim_dir: &Path,
        entries: &mut HashMap<String, HashMap<String, DkimEntry>>,
    ) -> Result<()> {
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
            let Ok(files) = std::fs::read_dir(&dir) else {
                continue;
            };
            for file in files.filter_map(|e| e.ok()) {
                if !file.file_type().map(|t| t.is_file()).unwrap_or(false) {
                    continue;
                }
                let selector_os = file.file_name();
                let Some(selector_str) = selector_os.to_str() else {
                    tracing::warn!(path = %file.path().display(), "skipping non-utf8 selector file");
                    continue;
                };
                let selector = selector_str.to_string();
                if !is_valid_selector(&selector) {
                    tracing::warn!(path = %file.path().display(), selector = %selector, "skipping file with invalid selector name (expected [A-Za-z0-9_-] 1..63)");
                    continue;
                }
                let path = file.path();
                // Permission check: fail if group/other have any access (0o077) like SSH
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let meta = std::fs::metadata(&path)?;
                    let mode = meta.permissions().mode();
                    if mode & 0o077 != 0 {
                        return Err(Error::Config(format!(
                            "insecure permissions {:o} on {}, private key must not be readable by group/other (chmod 600) like SSH",
                            mode & 0o777,
                            path.display()
                        )));
                    }
                }
                let key_pem = std::fs::read(&path)?;
                // Validate the key parses before accepting.
                parse_key(&key_pem).map_err(|e| {
                    Error::Config(format!("invalid DKIM key {} (selector {}): {e}", path.display(), selector))
                })?;

                let inner = entries.entry(domain.clone()).or_default();
                inner.insert(
                    selector.clone(),
                    DkimEntry {
                        domain: domain.clone(),
                        selector: selector.clone(),
                        key_pem,
                    },
                );
            }
        }
        Ok(())
    }

    /// Number of (domain,selector) keys.
    pub fn len(&self) -> usize {
        self.entries.values().map(|m| m.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() || self.entries.values().all(|m| m.is_empty())
    }

    /// True when a signing key exists for `domain` (any selector).
    pub fn has_signer(&self, domain: &str) -> bool {
        self.entries.get(domain).map(|m| !m.is_empty()).unwrap_or(false)
    }

    /// Build a ready-to-use DKIM signer for `domain`, signing the given
    /// `headers` (they should be a subset of the headers present in the
    /// message being signed). Selects selector via default_selector if present,
    /// else if exactly one selector exists uses it, otherwise fails.
    pub fn build_signer(&self, domain: &str, headers: &[&str]) -> Result<DkimSigner<DkimKey, Done>> {
        let inner = self
            .entries
            .get(domain)
            .ok_or_else(|| Error::Dkim(format!("no DKIM key for domain {domain}")))?;
        if inner.is_empty() {
            return Err(Error::Dkim(format!("no DKIM key for domain {domain}")));
        }
        let entry = if let Some(e) = inner.get(&self.default_selector) {
            e
        } else if inner.len() == 1 {
            inner.values().next().unwrap()
        } else {
            let mut selectors: Vec<String> = inner.keys().cloned().collect();
            selectors.sort();
            return Err(Error::Dkim(format!(
                "multiple DKIM keys for domain {domain} ({}) but none matches default selector {:?}; set dkim_selector_default or keep only one",
                selectors.join(", "),
                self.default_selector
            )));
        };
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

fn is_valid_selector(s: &str) -> bool {
    if s.is_empty() || s.len() > 63 {
        return false;
    }
    s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
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

    fn write_key(path: &std::path::Path, mode: u32) {
        std::fs::write(path, RSA_KEY).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
    }

    fn key_dir() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let domain_dir = dir.path().join("dkim/example.com");
        std::fs::create_dir_all(&domain_dir).unwrap();
        write_key(&domain_dir.join("mail2026"), 0o600);
        let dkim_root = dir.path().join("dkim");
        (dir, dkim_root)
    }

    #[test]
    fn loads_per_domain_keys() {
        let (dir, dkim) = key_dir();
        let manager = DkimManager::load(&dkim, "mail2026").unwrap();
        assert_eq!(manager.len(), 1);
        assert!(manager.has_signer("example.com"));
        assert!(!manager.has_signer("other.com"));
        drop(dir);
    }

    #[test]
    fn builds_signer() {
        let (dir, dkim) = key_dir();
        let manager = DkimManager::load(&dkim, "mail2026").unwrap();
        let signer = manager.build_signer("example.com", &["From", "To", "Subject"]);
        assert!(signer.is_ok());
        drop(dir);
    }

    #[test]
    fn parses_rsa_key() {
        let key = parse_key(RSA_KEY.as_bytes()).unwrap();
        assert!(matches!(key, DkimKey::Rsa(_)));
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

    #[test]
    fn multiple_selectors_picks_default() {
        let dir = tempfile::tempdir().unwrap();
        let domain_dir = dir.path().join("dkim/example.com");
        std::fs::create_dir_all(&domain_dir).unwrap();
        write_key(&domain_dir.join("default"), 0o600);
        write_key(&domain_dir.join("mail2026"), 0o600);
        let mgr = DkimManager::load(&dir.path().join("dkim"), "default").unwrap();
        assert_eq!(mgr.len(), 2);
        let signer = mgr.build_signer("example.com", &["From"]).unwrap();
        drop(dir);
        // ensure default picked (no error)
        let _ = signer;
    }

    #[test]
    fn single_selector_fallback_when_default_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let domain_dir = dir.path().join("dkim/example.com");
        std::fs::create_dir_all(&domain_dir).unwrap();
        write_key(&domain_dir.join("onlyone"), 0o600);
        let mgr = DkimManager::load(&dir.path().join("dkim"), "default").unwrap();
        // single file, default mismatch → should still succeed via fallback
        assert!(mgr.build_signer("example.com", &["From"]).is_ok());
        drop(dir);
    }

    #[test]
    fn fails_when_multiple_no_default() {
        let dir = tempfile::tempdir().unwrap();
        let domain_dir = dir.path().join("dkim/example.com");
        std::fs::create_dir_all(&domain_dir).unwrap();
        write_key(&domain_dir.join("a"), 0o600);
        write_key(&domain_dir.join("b"), 0o600);
        let mgr = DkimManager::load(&dir.path().join("dkim"), "missing").unwrap();
        assert!(mgr.build_signer("example.com", &["From"]).is_err());
        drop(dir);
    }

    #[test]
    fn rejects_insecure_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let domain_dir = dir.path().join("dkim/example.com");
        std::fs::create_dir_all(&domain_dir).unwrap();
        let p = domain_dir.join("default");
        write_key(&p, 0o644);
        let res = DkimManager::load(&dir.path().join("dkim"), "default");
        #[cfg(unix)]
        assert!(res.is_err());
        #[cfg(not(unix))]
        assert!(res.is_ok());
        drop(dir);
    }

    #[test]
    fn ignores_invalid_selector_name() {
        let dir = tempfile::tempdir().unwrap();
        let domain_dir = dir.path().join("dkim/example.com");
        std::fs::create_dir_all(&domain_dir).unwrap();
        // invalid selector with dot
        let bad = domain_dir.join("bad.selector");
        write_key(&bad, 0o600);
        write_key(&domain_dir.join("good"), 0o600);
        let mgr = DkimManager::load(&dir.path().join("dkim"), "good").unwrap();
        assert_eq!(mgr.len(), 1);
        assert!(mgr.has_signer("example.com"));
        drop(dir);
    }

    #[test]
    fn merged_load_user_overrides_system() {
        let sys = tempfile::tempdir().unwrap();
        let usr = tempfile::tempdir().unwrap();
        let sys_dom = sys.path().join("dkim/example.com");
        let usr_dom = usr.path().join("dkim/example.com");
        std::fs::create_dir_all(&sys_dom).unwrap();
        std::fs::create_dir_all(&usr_dom).unwrap();
        write_key(&sys_dom.join("default"), 0o600);
        // user overrides same selector with same key (counts as 1 but user wins) and adds extra
        write_key(&usr_dom.join("default"), 0o600);
        write_key(&usr_dom.join("extra"), 0o600);
        let mgr = DkimManager::load_merged(&sys.path().join("dkim"), &usr.path().join("dkim"), "default").unwrap();
        assert_eq!(mgr.len(), 2); // default (user) + extra
        drop(sys);
        drop(usr);
    }
}
