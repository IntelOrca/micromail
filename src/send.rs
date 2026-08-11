use crate::config::Config;
use crate::dkim::{DkimManager, headers_to_sign};
use crate::error::{Error, Result};
use mail_send::smtp::message::Message;
use mail_send::{Credentials, SmtpClient, SmtpClientBuilder};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

pub(crate) trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> AsyncReadWrite for T {}

pub(crate) type DynStream = Box<dyn AsyncReadWrite + Send + Sync + Unpin>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    Auto,
    Starttls,
    Tls,
    Plain,
}

impl TlsMode {
    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "auto" => Ok(TlsMode::Auto),
            "starttls" => Ok(TlsMode::Starttls),
            "tls" => Ok(TlsMode::Tls),
            "plain" => Ok(TlsMode::Plain),
            other => Err(Error::Config(format!(
                "invalid delivery.relay_tls value {other:?}; expected auto, starttls, tls or plain"
            ))),
        }
    }
}

#[derive(Clone)]
struct Relay {
    host: String,
    port: u16,
    tls: TlsMode,
    username: Option<String>,
    password: Option<String>,
}

/// Outbound delivery engine: MX resolution, TLS, DKIM signing and SMTP send.
pub struct Delivery {
    dkim: Arc<DkimManager>,
    relay: Option<Relay>,
    timeout: Duration,
}

impl Delivery {
    pub fn from_config(config: &Config, config_dir: &std::path::Path) -> Result<Self> {
        let dkim = if config.dkim.enabled {
            Arc::new(DkimManager::load(&config.dkim_dir(config_dir), &config.dkim_selector_default)?)
        } else {
            Arc::new(DkimManager::load(
                &std::path::PathBuf::new(),
                &config.dkim_selector_default,
            )?)
        };

        let relay = match &config.delivery.relay {
            Some(addr) => {
                let (host, port) = parse_host_port(addr)
                    .ok_or_else(|| Error::Config(format!("invalid delivery.relay {addr:?}")))?;
                Some(Relay {
                    host,
                    port,
                    tls: TlsMode::from_str(&config.delivery.relay_tls)?,
                    username: config.delivery.relay_username.clone(),
                    password: config.delivery.relay_password.clone(),
                })
            }
            None => None,
        };

        Ok(Delivery {
            dkim,
            relay,
            timeout: Duration::from_secs(config.delivery.timeout_secs.max(1)),
        })
    }

    pub fn dkim(&self) -> &DkimManager {
        &self.dkim
    }

    /// Delivery stub for tests: always fails fast against a closed port.
    #[cfg(test)]
    pub fn unused_for_tests() -> Self {
        Delivery {
            dkim: Arc::new(DkimManager::load(&std::path::PathBuf::new(), "default").unwrap()),
            relay: Some(Relay {
                host: "127.0.0.1".into(),
                port: 1,
                tls: TlsMode::Plain,
                username: None,
                password: None,
            }),
            timeout: Duration::from_secs(1),
        }
    }

    /// Deliver a message synchronously (single attempt).
    ///
    /// `from` is the envelope sender, `to` the envelope recipients and `body`
    /// the raw RFC 5322 message (headers + body).
    pub async fn deliver(&self, from: &str, to: &[String], body: &[u8]) -> Result<()> {
        if from.trim().is_empty() {
            return Err(Error::InvalidInput("empty envelope sender".into()));
        }
        if to.is_empty() {
            return Err(Error::InvalidInput("no recipients".into()));
        }

        let from_domain = email_domain(from).ok_or_else(|| {
            Error::InvalidInput(format!("invalid envelope sender address {from:?}"))
        })?;

        let message = Message::new(
            from.to_string(),
            to.iter().cloned(),
            body.to_vec(),
        );

        let signer = if self.dkim.has_signer(&from_domain) {
            let headers = headers_to_sign(body);
            if headers.is_empty() {
                tracing::warn!(domain = %from_domain, "DKIM key present but no signable headers found");
                None
            } else {
                Some(self.dkim.build_signer(&from_domain, &headers)?)
            }
        } else {
            None
        };

        let mut client = self.connect(&from_domain).await?;

        match signer {
            Some(signer) => {
                client.send_signed(message, &signer).await?;
            }
            None => {
                client.send(message).await?;
            }
        }

        Ok(())
    }

    async fn connect(&self, domain: &str) -> Result<SmtpClient<DynStream>> {
        if let Some(relay) = &self.relay {
            self.connect_target(&relay.host, relay.port, relay.tls, relay.username.as_deref(), relay.password.as_deref())
                .await
        } else {
            self.connect_to_mx(domain).await
        }
    }

    async fn connect_to_mx(&self, domain: &str) -> Result<SmtpClient<DynStream>> {
        let hosts = resolve_mx(domain).await?;
        let mut last_err = None;
        for host in &hosts {
            match self
                .connect_target(host, 25, TlsMode::Auto, None, None)
                .await
            {
                Ok(client) => return Ok(client),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| Error::Dns(format!("no MX hosts for {domain}"))))
    }

    async fn connect_target(
        &self,
        host: &str,
        port: u16,
        tls: TlsMode,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<SmtpClient<DynStream>> {
        match tls {
            TlsMode::Plain => {
                let client = make_builder(host, port, self.timeout, username, password)?
                    .connect_plain()
                    .await?;
                Ok(box_client(client))
            }
            TlsMode::Tls => {
                let client = make_builder(host, port, self.timeout, username, password)?
                    .implicit_tls(true)
                    .connect()
                    .await?;
                Ok(box_client(client))
            }
            TlsMode::Starttls => {
                let client = make_builder(host, port, self.timeout, username, password)?
                    .implicit_tls(false)
                    .connect()
                    .await?;
                Ok(box_client(client))
            }
            TlsMode::Auto => {
                if port == 465 {
                    let client = make_builder(host, port, self.timeout, username, password)?
                        .implicit_tls(true)
                        .connect()
                        .await?;
                    Ok(box_client(client))
                } else {
                    match make_builder(host, port, self.timeout, username, password)?
                        .implicit_tls(false)
                        .connect()
                        .await
                    {
                        Ok(client) => Ok(box_client(client)),
                        Err(mail_send::Error::MissingStartTls) => {
                            let client = make_builder(host, port, self.timeout, username, password)?
                                .connect_plain()
                                .await?;
                            Ok(box_client(client))
                        }
                        Err(e) => Err(e.into()),
                    }
                }
            }
        }
    }
}

fn make_builder<'a>(
    host: &'a str,
    port: u16,
    timeout: Duration,
    username: Option<&'a str>,
    password: Option<&'a str>,
) -> Result<SmtpClientBuilder<&'a str>> {
    let mut builder = SmtpClientBuilder::new(host, port)
        .map_err(Error::Send)?
        .timeout(timeout);
    if let (Some(u), Some(p)) = (username, password) {
        builder = builder.credentials(Credentials::Plain {
            username: u,
            secret: p,
        });
    }
    Ok(builder)
}

fn box_client<T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static>(
    client: SmtpClient<T>,
) -> SmtpClient<DynStream> {
    SmtpClient {
        stream: Box::new(client.stream),
        timeout: client.timeout,
    }
}

/// Resolve the MX hosts for a domain, sorted by preference (lowest first).
/// Falls back to the domain itself when no MX records exist.
async fn resolve_mx(domain: &str) -> Result<Vec<String>> {
    use hickory_resolver::TokioResolver;

    let resolver = TokioResolver::builder_tokio()
        .map_err(|e| Error::Dns(e.to_string()))?
        .build()
        .map_err(|e| Error::Dns(e.to_string()))?;

    match resolver.mx_lookup(domain).await {
        Ok(lookup) => {
            let mut hosts: Vec<(u16, String)> = lookup
                .answers()
                .iter()
                .filter_map(|record| match &record.data {
                    hickory_resolver::proto::rr::RData::MX(mx) => Some((
                        mx.preference,
                        mx.exchange.to_string().trim_end_matches('.').to_string(),
                    )),
                    _ => None,
                })
                .collect();
            hosts.sort_by_key(|(pref, _)| *pref);
            if hosts.is_empty() {
                Ok(vec![domain.to_string()])
            } else {
                Ok(hosts.into_iter().map(|(_, host)| host).collect())
            }
        }
        Err(_) => {
            // No MX record: fall back to an A/AAAA lookup of the domain itself.
            match resolver.lookup_ip(domain).await {
                Ok(_) => Ok(vec![domain.to_string()]),
                Err(_) => Err(Error::Dns(format!("cannot resolve mail host for {domain}"))),
            }
        }
    }
}

/// Extract the domain part of an email address, lowercased.
pub fn email_domain(address: &str) -> Option<String> {
    let address = address.trim();
    let at = address.rfind('@')?;
    let domain = address[at + 1..].trim();
    if domain.is_empty() || domain.contains(' ') {
        return None;
    }
    let domain = domain.trim_end_matches('.');
    if domain.is_empty() {
        None
    } else {
        Some(domain.to_lowercase())
    }
}

/// Split a "host:port" string. Port defaults to 25 when omitted.
pub fn parse_host_port(addr: &str) -> Option<(String, u16)> {
    let addr = addr.trim();
    if addr.is_empty() {
        return None;
    }
    if let Some((host, port)) = addr.rsplit_once(':') {
        if host.is_empty() || host.contains(' ') {
            return None;
        }
        let port: u16 = port.trim().parse().ok()?;
        Some((host.to_string(), port))
    } else {
        Some((addr.to_string(), 25))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_host_port() {
        assert_eq!(
            parse_host_port("smtp.example.com:587"),
            Some(("smtp.example.com".to_string(), 587))
        );
        assert_eq!(
            parse_host_port("smtp.example.com"),
            Some(("smtp.example.com".to_string(), 25))
        );
        assert_eq!(parse_host_port(""), None);
        assert_eq!(parse_host_port(":bad"), None);
    }

    #[test]
    fn extracts_email_domain() {
        assert_eq!(email_domain("user@Example.COM"), Some("example.com".into()));
        assert_eq!(
            email_domain("user@example.com."),
            Some("example.com".into())
        );
        assert_eq!(email_domain("no-at-sign"), None);
        assert_eq!(email_domain("user@"), None);
    }

    #[test]
    fn tls_mode_parsing() {
        assert_eq!(TlsMode::from_str("auto").unwrap(), TlsMode::Auto);
        assert_eq!(TlsMode::from_str("STARTTLS").unwrap(), TlsMode::Starttls);
        assert!(TlsMode::from_str("bogus").is_err());
    }
}
