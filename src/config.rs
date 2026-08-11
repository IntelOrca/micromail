use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const DEFAULT_CONFIG_DIR: &str = "/etc/micromail";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Log level (trace, debug, info, warn, error).
    pub log: String,
    /// Hostname used in the SMTP greeting and EHLO response.
    pub hostname: String,
    /// Maximum size in bytes of a single message accepted by the SMTP server.
    pub max_message_size: usize,
    /// Maximum number of recipients per message (SMTP + REST).
    pub max_recipients: usize,
    /// Default DKIM selector used when a domain has no `selector` file.
    pub dkim_selector_default: String,

    pub smtp: SmtpConfig,
    pub api: ApiConfig,
    pub dkim: DkimConfig,
    pub delivery: DeliveryConfig,
    pub retry: RetryConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SmtpConfig {
    /// Serve the SMTP submission endpoint.
    pub enabled: bool,
    /// Address to bind for plain + STARTTLS submission (usually :587).
    pub listen: String,
    /// Address to bind for implicit-TLS submission (usually :465).
    /// Only used when a certificate is configured.
    pub tls_listen: String,
    /// TLS certificate file. Defaults to <config dir>/tls/cert.pem.
    pub cert: Option<PathBuf>,
    /// TLS private key file. Defaults to <config dir>/tls/key.pem.
    pub key: Option<PathBuf>,
    /// Authentication users allowed to submit mail.
    pub users: Vec<SmtpUser>,
}

impl Default for SmtpConfig {
    fn default() -> Self {
        SmtpConfig {
            enabled: false,
            listen: "0.0.0.0:587".into(),
            tls_listen: "0.0.0.0:465".into(),
            cert: None,
            key: None,
            users: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpUser {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ApiConfig {
    /// Serve the REST API.
    pub enabled: bool,
    /// Address to bind for the REST API (usually :8080).
    pub listen: String,
    /// Bearer tokens accepted by the REST API.
    pub tokens: Vec<String>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        ApiConfig {
            enabled: false,
            listen: "0.0.0.0:8080".into(),
            tokens: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DkimConfig {
    /// Enable DKIM signing.
    pub enabled: bool,
}

impl Default for DkimConfig {
    fn default() -> Self {
        DkimConfig { enabled: true }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DeliveryConfig {
    /// Optional SMTP relay host, e.g. "smtp.provider.com:587".
    /// When unset, mail is delivered directly to the recipient's MX.
    pub relay: Option<String>,
    /// Optional username for relay authentication.
    pub relay_username: Option<String>,
    /// Optional password for relay authentication.
    pub relay_password: Option<String>,
    /// TLS mode for the relay: "auto", "starttls", "tls" or "plain".
    /// "auto" uses implicit TLS for port 465 and STARTTLS elsewhere,
    /// falling back to plaintext when STARTTLS is not advertised.
    pub relay_tls: String,
    /// Outbound timeout in seconds.
    pub timeout_secs: u64,
}

impl Default for DeliveryConfig {
    fn default() -> Self {
        DeliveryConfig {
            relay: None,
            relay_username: None,
            relay_password: None,
            relay_tls: "auto".into(),
            timeout_secs: 300,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RetryConfig {
    /// Maximum delivery attempts before a message is marked failed.
    pub max_attempts: usize,
    /// Delay before the first retry, in seconds.
    pub initial_delay_secs: u64,
    /// Multiplier applied to the delay on each retry.
    pub backoff_factor: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        RetryConfig {
            max_attempts: 5,
            initial_delay_secs: 60,
            backoff_factor: 2,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            log: "info".into(),
            hostname: "localhost".into(),
            max_message_size: 25 * 1024 * 1024,
            max_recipients: 100,
            dkim_selector_default: "default".into(),
            smtp: SmtpConfig::default(),
            api: ApiConfig::default(),
            dkim: DkimConfig::default(),
            delivery: DeliveryConfig::default(),
            retry: RetryConfig::default(),
        }
    }
}

impl Config {
    /// Load configuration from a directory. A `config.toml` inside the
    /// directory is optional; when absent, defaults are used.
    pub fn load(dir: &Path) -> Result<Config> {
        let path = dir.join("config.toml");
        let mut config = match std::fs::read(&path) {
            Ok(bytes) => toml::from_slice(&bytes)
                .map_err(|e| Error::Config(format!("invalid {}: {e}", path.display())))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Config::default(),
            Err(e) => return Err(Error::Config(format!("cannot read {}: {e}", path.display()))),
        };

        config.resolve_paths(dir);
        Ok(config)
    }

    /// Resolve TLS certificate paths from the config dir when not set.
    fn resolve_paths(&mut self, dir: &Path) {
        if self.smtp.cert.is_none() {
            for candidate in [dir.join("tls/cert.pem"), dir.join("cert.pem")] {
                if candidate.exists() {
                    self.smtp.cert = Some(candidate);
                    break;
                }
            }
        }
        if self.smtp.key.is_none() {
            for candidate in [dir.join("tls/key.pem"), dir.join("key.pem")] {
                if candidate.exists() {
                    self.smtp.key = Some(candidate);
                    break;
                }
            }
        }
    }

    /// True when the SMTP submission server should present TLS.
    pub fn smtp_tls_enabled(&self) -> bool {
        self.smtp.cert.is_some() && self.smtp.key.is_some()
    }

    /// Directory holding per-domain DKIM keys: `<config dir>/dkim`.
    pub fn dkim_dir(&self, dir: &Path) -> PathBuf {
        dir.join("dkim")
    }

    /// Directory holding the on-disk delivery spool: `<config dir>/spool`.
    pub fn spool_dir(&self, dir: &Path) -> PathBuf {
        dir.join("spool")
    }

    /// Directory where permanently failed messages are parked.
    pub fn failed_dir(&self, dir: &Path) -> PathBuf {
        dir.join("spool").join("failed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_when_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::load(dir.path()).unwrap();
        assert_eq!(config.hostname, "localhost");
        assert!(!config.smtp.enabled);
        assert!(!config.api.enabled);
        assert_eq!(config.retry.max_attempts, 5);
    }

    #[test]
    fn parses_full_config() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("config.toml"),
            r#"
hostname = "mail.example.com"
max_recipients = 25

[smtp]
enabled = true
listen = "0.0.0.0:2525"

[[smtp.users]]
username = "app"
password = "hunter2"

[api]
enabled = true
tokens = ["tok-1", "tok-2"]

[delivery]
relay = "smtp.provider.com:587"
relay_username = "u"
relay_password = "p"

[retry]
max_attempts = 3
initial_delay_secs = 5
backoff_factor = 3
"#,
        )
        .unwrap();

        let config = Config::load(dir.path()).unwrap();
        assert_eq!(config.hostname, "mail.example.com");
        assert_eq!(config.max_recipients, 25);
        assert!(config.smtp.enabled);
        assert_eq!(config.smtp.listen, "0.0.0.0:2525");
        assert_eq!(config.smtp.users.len(), 1);
        assert_eq!(config.smtp.users[0].username, "app");
        assert!(config.api.enabled);
        assert_eq!(config.api.tokens, vec!["tok-1".to_string(), "tok-2".to_string()]);
        assert_eq!(
            config.delivery.relay.as_deref(),
            Some("smtp.provider.com:587")
        );
        assert_eq!(config.retry.max_attempts, 3);
        assert_eq!(config.retry.backoff_factor, 3);
    }

    #[test]
    fn detects_tls_certs_in_config_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("tls")).unwrap();
        std::fs::write(dir.path().join("tls/cert.pem"), "cert").unwrap();
        std::fs::write(dir.path().join("tls/key.pem"), "key").unwrap();
        let config = Config::load(dir.path()).unwrap();
        assert!(config.smtp_tls_enabled());
    }
}
