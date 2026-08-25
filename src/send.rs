use crate::config::Config;
use crate::dkim::{headers_to_sign, DkimManager, DkimSigner};
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
    /// Shared DNS resolver (re-reads resolv.conf only once, at construction).
    resolver: hickory_resolver::TokioResolver,
}

impl Delivery {
    pub fn from_config(config: &Config, config_dir: &std::path::Path) -> Result<Self> {
        let dkim = if config.dkim.enabled {
            let user_dkim = config.dkim_dir(config_dir);
            let system_dkim =
                std::path::PathBuf::from(crate::config::SYSTEM_CONFIG_DIR).join("dkim");
            let default_user = crate::config::default_config_dir();
            let dkim = if config_dir == default_user
                && config_dir != std::path::Path::new(crate::config::SYSTEM_CONFIG_DIR)
            {
                Arc::new(DkimManager::load_merged(
                    &system_dkim,
                    &user_dkim,
                    &config.dkim_selector_default,
                )?)
            } else {
                Arc::new(DkimManager::load(
                    &user_dkim,
                    &config.dkim_selector_default,
                )?)
            };
            dkim
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

        let resolver = build_resolver()?;

        Ok(Delivery {
            dkim,
            relay,
            timeout: Duration::from_secs(config.delivery.timeout_secs.max(1)),
            resolver,
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
            resolver: build_resolver().expect("test resolver"),
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
        let signer = signer.as_ref();

        if let Some(relay) = &self.relay {
            tracing::info!(
                relay = %relay.host,
                port = relay.port,
                tls = ?relay.tls,
                "delivering via relay"
            );
            let message_body = sign_message_if_needed(body, signer)?;
            let message = Message::new(from.to_string(), to.iter().cloned(), message_body);
            let mut client = self
                .connect_target(
                    &relay.host,
                    relay.port,
                    relay.tls,
                    relay.username.as_deref(),
                    relay.password.as_deref(),
                )
                .await?;
            return self.send_message(&mut client, message).await;
        }

        self.deliver_direct(from, to, body, signer).await
    }

    /// Deliver directly to the recipient MX servers. Recipients are grouped by
    /// domain and each group is sent over a connection to that domain's MX.
    ///
    /// A failed domain does not abort the remaining domains: when at least one
    /// group succeeded, [`Error::PartialDelivery`] reports which recipients
    /// still need (re)delivery so retries never duplicate delivered mail.
    async fn deliver_direct(
        &self,
        from: &str,
        to: &[String],
        body: &[u8],
        signer: Option<&DkimSigner>,
    ) -> Result<()> {
        let mut groups: Vec<(String, Vec<String>)> = Vec::new();
        for rcpt in to {
            let domain = email_domain(rcpt).ok_or_else(|| {
                Error::InvalidInput(format!("invalid recipient address {rcpt:?}"))
            })?;
            match groups.iter_mut().find(|(d, _)| *d == domain) {
                Some((_, list)) => list.push(rcpt.clone()),
                None => groups.push((domain, vec![rcpt.clone()])),
            }
        }

        let mut delivered: Vec<String> = Vec::new();
        let mut remaining: Vec<String> = Vec::new();
        let mut first_err: Option<Error> = None;

        for (domain, rcpts) in &groups {
            match self
                .deliver_domain_group(from, domain, rcpts, body, signer)
                .await
            {
                Ok(()) => delivered.extend(rcpts.iter().cloned()),
                Err(e) => {
                    tracing::warn!(domain = %domain, err = %e, "domain delivery failed");
                    remaining.extend(rcpts.iter().cloned());
                    first_err.get_or_insert(e);
                }
            }
        }

        match first_err {
            None => Ok(()),
            Some(source) => Err(Error::PartialDelivery {
                delivered,
                remaining,
                source: Box::new(source),
            }),
        }
    }

    /// Deliver one per-domain recipient group over a connection to its MX.
    async fn deliver_domain_group(
        &self,
        from: &str,
        domain: &str,
        rcpts: &[String],
        body: &[u8],
        signer: Option<&DkimSigner>,
    ) -> Result<()> {
        let hosts = self.resolve_mx(domain).await?;
        tracing::debug!(domain = %domain, hosts = ?hosts, "resolved MX hosts");

        let mut last_err = None;
        let mut client = None;
        for host in &hosts {
            match self
                .connect_target(host, 25, TlsMode::Auto, None, None)
                .await
            {
                Ok(c) => {
                    client = Some(c);
                    break;
                }
                Err(e) => {
                    tracing::debug!(host = %host, err = %e, "MX connection failed; trying next");
                    last_err = Some(e);
                }
            }
        }
        let Some(mut client) = client else {
            return Err(last_err
                .unwrap_or_else(|| Error::Dns(format!("no reachable MX host for {domain}"))));
        };

        tracing::info!(domain = %domain, rcpts = rcpts.len(), "delivering to domain MX");
        let message_body = sign_message_if_needed(body, signer)?;
        let message = Message::new(from.to_string(), rcpts.iter().cloned(), message_body);
        self.send_message(&mut client, message).await
    }

    /// Resolve the MX hosts for a domain, sorted by preference (lowest first).
    /// Falls back to the domain itself when no MX records exist.
    async fn resolve_mx(&self, domain: &str) -> Result<Vec<String>> {
        let resolver = &self.resolver;

        tracing::debug!(domain = %domain, "resolving MX records");

        match resolver.mx_lookup(domain).await {
            Ok(lookup) => {
                let mut hosts: Vec<(u16, String)> = lookup
                    .answers()
                    .iter()
                    .filter_map(|record| match &record.data {
                        hickory_resolver::proto::rr::RData::MX(mx) => {
                            let host = mx.exchange.to_string().trim_end_matches('.').to_string();
                            if host.is_empty() {
                                // Null MX (RFC 7505, e.g. example.com "0 .") — no mail.
                                None
                            } else {
                                Some((mx.preference, host))
                            }
                        }
                        _ => None,
                    })
                    .collect();
                if hosts.is_empty() {
                    // No usable MX (including Null MX 0 .): do not fall back to A
                    // per RFC 7505 — fail rather than delivering to the apex A record.
                    return Err(Error::Dns(format!(
                        "domain {domain} has no mail exchanger (null MX)"
                    )));
                }
                hosts.sort_by_key(|(pref, _)| *pref);
                Ok(hosts.into_iter().map(|(_, host)| host).collect())
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

    async fn send_message<'x>(
        &self,
        client: &mut SmtpClient<DynStream>,
        message: Message<'x>,
    ) -> Result<()> {
        client.send(message).await?;
        Ok(())
    }

    async fn connect_target(
        &self,
        host: &str,
        port: u16,
        tls: TlsMode,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Result<SmtpClient<DynStream>> {
        tracing::debug!(host = %host, port, tls = ?tls, "connecting to SMTP server");
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
                            let client =
                                make_builder(host, port, self.timeout, username, password)?
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

fn sign_message_if_needed(body: &[u8], signer: Option<&DkimSigner>) -> Result<Vec<u8>> {
    if let Some(signer) = signer {
        let dkim_header = signer.sign(body)?;
        Ok(insert_dkim_header(body, &dkim_header))
    } else {
        Ok(body.to_vec())
    }
}

fn insert_dkim_header(original: &[u8], dkim_header: &str) -> Vec<u8> {
    let header_bytes = dkim_header.as_bytes();
    // Find header/body split
    if let Some(pos) = original.windows(4).position(|w| w == b"\r\n\r\n") {
        let mut out = Vec::with_capacity(original.len() + header_bytes.len() + 2);
        out.extend_from_slice(&original[..pos]);
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(header_bytes);
        out.extend_from_slice(&original[pos..]);
        out
    } else if let Some(pos) = original.windows(2).position(|w| w == b"\n\n") {
        let mut out = Vec::with_capacity(original.len() + header_bytes.len() + 2);
        out.extend_from_slice(&original[..pos]);
        out.extend_from_slice(b"\n");
        out.extend_from_slice(header_bytes);
        out.extend_from_slice(&original[pos..]);
        out
    } else {
        // No body, just append
        let mut out = Vec::with_capacity(original.len() + header_bytes.len() + 2);
        out.extend_from_slice(header_bytes);
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(original);
        out
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

/// Build the shared DNS resolver used for MX lookups.
fn build_resolver() -> Result<hickory_resolver::TokioResolver> {
    hickory_resolver::TokioResolver::builder_tokio()
        .map_err(|e| Error::Dns(e.to_string()))?
        .build()
        .map_err(|e| Error::Dns(e.to_string()))
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

    #[test]
    fn inserts_dkim_header() {
        let msg = b"From: a@example.com\r\nTo: b@example.com\r\nSubject: Hi\r\n\r\nbody\r\n";
        let dkim = "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=test; bh=abc; b=def";
        let out = insert_dkim_header(msg, dkim);
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("DKIM-Signature:"));
        assert!(s.contains("From: a@example.com"));
        // DKIM should be between existing headers and body
        let dkim_pos = s.find("DKIM-Signature:").unwrap();
        let from_pos = s.find("From:").unwrap();
        let body_pos = s.find("\r\n\r\n").unwrap();
        assert!(dkim_pos > from_pos && dkim_pos < body_pos);
    }
}
