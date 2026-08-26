use crate::config::{Config, SmtpUser};
use crate::error::Result;
use crate::queue::Spool;
use crate::send::DynStream;
use crate::smtp_auth;
use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(300);
const DATA_TIMEOUT: Duration = Duration::from_secs(600);
const MAX_COMMAND_LEN: usize = 512;
const DATA_TERM: &[u8] = b"\r\n.\r\n";
const DATA_TERM_LF: &[u8] = b"\n.\n";

/// The SMTP submission server. Accepts authenticated clients on :587
/// (plain or STARTTLS) and optionally on :465 (implicit TLS).
pub struct SmtpServer {
    config: Arc<Config>,
    spool: Arc<Spool>,
    tls: Option<Arc<TlsAcceptor>>,
}

impl SmtpServer {
    pub fn new(config: Arc<Config>, spool: Arc<Spool>) -> Result<Self> {
        let tls = match config.smtp_tls_paths() {
            Some((cert, key)) => Some(Arc::new(load_tls_acceptor(cert, key)?)),
            None => None,
        };
        Ok(SmtpServer { config, spool, tls })
    }

    /// Bind the configured listeners and accept connections until the
    /// shutdown signal fires.
    pub async fn run(self, shutdown: watch::Receiver<bool>) -> Result<()> {
        let session = Arc::new(Session {
            hostname: self.config.hostname.clone(),
            users: self.config.smtp.users.clone(),
            max_message_size: self.config.max_message_size,
            max_recipients: self.config.max_recipients,
            spool: self.spool.clone(),
            tls: self.tls.clone(),
            allow_auth_insecure: self.config.smtp.allow_auth_insecure,
        });

        let mut tasks = Vec::new();

        if self.config.smtp.enabled {
            let listener = TcpListener::bind(&self.config.smtp.listen)
                .await
                .map_err(|e| {
                    crate::error::Error::Config(format!(
                        "cannot bind smtp.listen {}: {e}",
                        self.config.smtp.listen
                    ))
                })?;
            tracing::info!(listen = %self.config.smtp.listen, "SMTP submission server listening");
            tasks.push(tokio::spawn(accept_loop(
                listener,
                session.clone(),
                shutdown.clone(),
            )));
        }

        if self.tls.is_some() && self.config.smtp.enabled {
            let listener = TcpListener::bind(&self.config.smtp.tls_listen)
                .await
                .map_err(|e| {
                    crate::error::Error::Config(format!(
                        "cannot bind smtp.tls_listen {}: {e}",
                        self.config.smtp.tls_listen
                    ))
                })?;
            tracing::info!(listen = %self.config.smtp.tls_listen, "SMTP implicit-TLS server listening");
            tasks.push(tokio::spawn(accept_loop(
                listener,
                session.clone(),
                shutdown.clone(),
            )));
        }

        // Wait for shutdown, then let active connections wind down briefly.
        let mut shutdown = shutdown;
        while !*shutdown.borrow() {
            if shutdown.changed().await.is_err() {
                break;
            }
        }
        for task in tasks {
            let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
        }
        Ok(())
    }
}

struct Session {
    hostname: String,
    users: Vec<SmtpUser>,
    max_message_size: usize,
    max_recipients: usize,
    spool: Arc<Spool>,
    tls: Option<Arc<TlsAcceptor>>,
    allow_auth_insecure: bool,
}

#[derive(Default)]
struct ConnState {
    ehlo: bool,
    authenticated: bool,
    tls_active: bool,
    mail_from: Option<String>,
    rcpt_to: Vec<String>,
    auth_phase: Option<AuthPhase>,
}

enum AuthPhase {
    PlainChallenge,
    LoginUsername,
    LoginPassword(String),
}

async fn accept_loop(
    listener: TcpListener,
    session: Arc<Session>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                tracing::info!("SMTP listener shutting down");
                break;
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, addr)) => {
                        tracing::debug!(peer = %addr, "SMTP connection accepted");
                        let session = session.clone();
                        tokio::spawn(async move {
                            let stream = StreamBuf::new(Box::new(stream) as DynStream);
                            if let Err(e) = handle(stream, session).await {
                                tracing::debug!(peer = %addr, "SMTP session ended: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("SMTP accept error: {e}");
                    }
                }
            }
        }
    }
}

async fn handle(mut stream: StreamBuf<DynStream>, session: Arc<Session>) -> Result<()> {
    write_reply(
        &mut stream.inner,
        &format!("220 {} ESMTP micromail\r\n", session.hostname),
    )
    .await?;

    let mut state = ConnState::default();

    loop {
        let line = match timeout(COMMAND_TIMEOUT, stream.read_line(MAX_COMMAND_LEN)).await {
            Ok(Ok(Some(line))) => line,
            Ok(Ok(None)) | Ok(Err(_)) => return Ok(()),
            Err(_) => return Ok(()), // idle timeout
        };

        let text = String::from_utf8_lossy(&line);
        let text = text.trim_end_matches(['\r', '\n']);

        if text.is_empty() {
            write_reply(&mut stream.inner, "500 5.5.2 Unrecognized command\r\n").await?;
            continue;
        }

        // AUTH continuation phase.
        if let Some(phase) = state.auth_phase.take() {
            match phase {
                AuthPhase::PlainChallenge => match smtp_auth::decode_plain(text) {
                    Ok((user, pass)) => {
                        if smtp_auth::authenticate(&session.users, &user, &pass) {
                            finish_auth(&mut state, user);
                            write_reply(
                                &mut stream.inner,
                                "235 2.7.0 Authentication successful\r\n",
                            )
                            .await?;
                        } else {
                            write_reply(
                                &mut stream.inner,
                                "535 5.7.8 Authentication credentials invalid\r\n",
                            )
                            .await?;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("AUTH PLAIN error: {e}");
                        write_reply(&mut stream.inner, "501 5.5.4 Invalid AUTH response\r\n")
                            .await?;
                    }
                },
                AuthPhase::LoginUsername => match smtp_auth::decode_b64(text) {
                    Ok(user) => {
                        state.auth_phase = Some(AuthPhase::LoginPassword(user));
                        write_reply(
                            &mut stream.inner,
                            &format!("334 {}\r\n", smtp_auth::encode_challenge("Password:")),
                        )
                        .await?;
                    }
                    Err(_) => {
                        write_reply(&mut stream.inner, "501 5.5.4 Invalid AUTH response\r\n")
                            .await?;
                    }
                },
                AuthPhase::LoginPassword(user) => match smtp_auth::decode_b64(text) {
                    Ok(pass) => {
                        if smtp_auth::authenticate(&session.users, &user, &pass) {
                            finish_auth(&mut state, user);
                            write_reply(
                                &mut stream.inner,
                                "235 2.7.0 Authentication successful\r\n",
                            )
                            .await?;
                        } else {
                            write_reply(
                                &mut stream.inner,
                                "535 5.7.8 Authentication credentials invalid\r\n",
                            )
                            .await?;
                        }
                    }
                    Err(_) => {
                        write_reply(&mut stream.inner, "501 5.5.4 Invalid AUTH response\r\n")
                            .await?;
                    }
                },
            }
            continue;
        }

        let (cmd, arg) = match text.split_once(' ') {
            Some((cmd, arg)) => (cmd, Some(arg.trim())),
            None => (text, None),
        };
        let cmd = cmd.to_ascii_uppercase();

        match cmd.as_str() {
            "EHLO" => {
                state.ehlo = true;
                write_reply(&mut stream.inner, &ehlo_reply(&session, state.tls_active)).await?;
            }
            "HELO" => {
                state.ehlo = true;
                write_reply(&mut stream.inner, &format!("250 {}\r\n", session.hostname)).await?;
            }
            "AUTH" => {
                if !state.ehlo {
                    write_reply(&mut stream.inner, "503 5.5.1 Bad sequence of commands\r\n")
                        .await?;
                    continue;
                }
                if session.users.is_empty() {
                    write_reply(&mut stream.inner, "503 5.5.1 AUTH not available\r\n").await?;
                    continue;
                }
                if !state.tls_active && !session.allow_auth_insecure {
                    write_reply(
                        &mut stream.inner,
                        "538 5.7.11 Encryption required for authentication\r\n",
                    )
                    .await?;
                    continue;
                }
                let (mech, inline_token) = match arg {
                    Some(a) => {
                        let mut parts = a.split_whitespace();
                        let m = parts.next().unwrap_or("").to_ascii_uppercase();
                        let t = parts.next().map(|s| s.to_string());
                        (m, t)
                    }
                    None => (String::new(), None),
                };
                match mech.as_str() {
                    "PLAIN" => {
                        // optional base64 argument inline, else 334 empty challenge
                        if let Some(token) = inline_token {
                            match smtp_auth::decode_plain(&token) {
                                Ok((user, pass)) => {
                                    if smtp_auth::authenticate(&session.users, &user, &pass) {
                                        finish_auth(&mut state, user);
                                        write_reply(
                                            &mut stream.inner,
                                            "235 2.7.0 Authentication successful\r\n",
                                        )
                                        .await?;
                                    } else {
                                        write_reply(
                                            &mut stream.inner,
                                            "535 5.7.8 Authentication credentials invalid\r\n",
                                        )
                                        .await?;
                                    }
                                }
                                Err(_) => {
                                    write_reply(
                                        &mut stream.inner,
                                        "501 5.5.4 Invalid AUTH response\r\n",
                                    )
                                    .await?;
                                }
                            }
                        } else {
                            state.auth_phase = Some(AuthPhase::PlainChallenge);
                            write_reply(&mut stream.inner, "334 \r\n").await?;
                        }
                    }
                    "LOGIN" => {
                        if let Some(token) = inline_token {
                            // Some clients send initial username inline: AUTH LOGIN <b64user>
                            match smtp_auth::decode_b64(&token) {
                                Ok(user) => {
                                    state.auth_phase = Some(AuthPhase::LoginPassword(user));
                                    write_reply(
                                        &mut stream.inner,
                                        &format!(
                                            "334 {}\r\n",
                                            smtp_auth::encode_challenge("Password:")
                                        ),
                                    )
                                    .await?;
                                }
                                Err(_) => {
                                    write_reply(
                                        &mut stream.inner,
                                        "501 5.5.4 Invalid AUTH response\r\n",
                                    )
                                    .await?;
                                }
                            }
                        } else {
                            state.auth_phase = Some(AuthPhase::LoginUsername);
                            write_reply(
                                &mut stream.inner,
                                &format!("334 {}\r\n", smtp_auth::encode_challenge("Username:")),
                            )
                            .await?;
                        }
                    }
                    _ => {
                        write_reply(
                            &mut stream.inner,
                            "504 5.5.4 Unsupported authentication mechanism\r\n",
                        )
                        .await?;
                    }
                }
            }
            "STARTTLS" => {
                if state.tls_active {
                    write_reply(&mut stream.inner, "503 5.5.1 TLS already active\r\n").await?;
                } else if let Some(acceptor) = &session.tls {
                    write_reply(&mut stream.inner, "220 2.0.0 Ready to start TLS\r\n").await?;
                    stream.inner.flush().await?;
                    match timeout(DATA_TIMEOUT, acceptor.accept(stream.into_inner())).await {
                        Ok(Ok(tls_stream)) => {
                            tracing::debug!("SMTP connection upgraded to TLS");
                            stream = StreamBuf::new(Box::new(tls_stream) as DynStream);
                            state = ConnState {
                                tls_active: true,
                                ..ConnState::default()
                            };
                            // Per RFC 3207 the client must EHLO again; the
                            // loop continues with the upgraded stream.
                            continue;
                        }
                        Ok(Err(e)) => {
                            tracing::warn!("STARTTLS handshake failed: {e}");
                            return Ok(());
                        }
                        Err(_) => return Ok(()),
                    }
                } else {
                    write_reply(&mut stream.inner, "454 4.7.0 TLS not available\r\n").await?;
                }
            }
            "MAIL" => {
                if !require_ready(&mut stream.inner, &state).await? {
                    continue;
                }
                let addr = parse_path_address(arg);
                let Some(addr) = addr.filter(|a| !a.is_empty()) else {
                    write_reply(&mut stream.inner, "501 5.5.4 Invalid MAIL FROM address\r\n")
                        .await?;
                    continue;
                };
                // Honor the SIZE parameter we advertise via EHLO.
                if let Some(size) = declared_size(arg) {
                    if size > session.max_message_size {
                        write_reply(
                            &mut stream.inner,
                            "552 5.3.4 Message size exceeds fixed maximum message size\r\n",
                        )
                        .await?;
                        continue;
                    }
                }
                state.rcpt_to.clear();
                state.mail_from = Some(addr);
                write_reply(&mut stream.inner, "250 2.1.0 Ok\r\n").await?;
            }
            "RCPT" => {
                if !require_ready(&mut stream.inner, &state).await? {
                    continue;
                }
                if state.mail_from.is_none() {
                    write_reply(&mut stream.inner, "503 5.5.1 Need MAIL before RCPT\r\n").await?;
                    continue;
                }
                if state.rcpt_to.len() >= session.max_recipients {
                    write_reply(&mut stream.inner, "452 4.5.3 Too many recipients\r\n").await?;
                    continue;
                }
                let addr = parse_path_address(arg);
                let Some(addr) = addr.filter(|a| !a.is_empty()) else {
                    write_reply(&mut stream.inner, "501 5.5.4 Invalid RCPT TO address\r\n").await?;
                    continue;
                };
                state.rcpt_to.push(addr);
                write_reply(&mut stream.inner, "250 2.1.5 Ok\r\n").await?;
            }
            "DATA" => {
                if !require_ready(&mut stream.inner, &state).await? {
                    continue;
                }
                if state.mail_from.is_none() || state.rcpt_to.is_empty() {
                    write_reply(
                        &mut stream.inner,
                        "503 5.5.1 Need MAIL and RCPT before DATA\r\n",
                    )
                    .await?;
                    continue;
                }
                write_reply(&mut stream.inner, "354 End data with <CR><LF>.<CR><LF>\r\n").await?;
                stream.inner.flush().await?;

                let body = match timeout(DATA_TIMEOUT, stream.read_data(session.max_message_size))
                    .await
                {
                    Ok(Ok(Some(body))) => body,
                    Ok(Ok(None)) => {
                        write_reply(
                            &mut stream.inner,
                            "451 4.4.1 Connection lost while reading message\r\n",
                        )
                        .await?;
                        continue;
                    }
                    Ok(Err(e)) => {
                        let too_large = e.kind() == std::io::ErrorKind::InvalidData;
                        if too_large {
                            write_reply(
                                &mut stream.inner,
                                "552 5.3.4 Message size exceeds limit\r\n",
                            )
                            .await?;
                        } else {
                            write_reply(&mut stream.inner, "451 4.3.0 Error reading message\r\n")
                                .await?;
                        }
                        continue;
                    }
                    Err(_) => {
                        write_reply(
                            &mut stream.inner,
                            "451 4.4.2 Timeout while reading message\r\n",
                        )
                        .await?;
                        continue;
                    }
                };

                let mail_from = state.mail_from.clone().unwrap_or_default();
                let rcpt_to = state.rcpt_to.clone();
                match session.spool.enqueue(mail_from, rcpt_to, body).await {
                    Ok(id) => {
                        tracing::info!(id = %id, "message accepted from SMTP");
                        write_reply(
                            &mut stream.inner,
                            &format!("250 2.0.0 Ok: queued as {id}\r\n"),
                        )
                        .await?;
                        state.mail_from = None;
                        state.rcpt_to.clear();
                    }
                    Err(e) => {
                        tracing::error!("failed to spool SMTP message: {e}");
                        write_reply(&mut stream.inner, "451 4.3.0 Temporary local error\r\n")
                            .await?;
                    }
                }
            }
            "RSET" => {
                state.mail_from = None;
                state.rcpt_to.clear();
                state.auth_phase = None;
                write_reply(&mut stream.inner, "250 2.0.0 Ok\r\n").await?;
            }
            "NOOP" => {
                write_reply(&mut stream.inner, "250 2.0.0 Ok\r\n").await?;
            }
            "QUIT" => {
                write_reply(&mut stream.inner, "221 2.0.0 Bye\r\n").await?;
                stream.inner.flush().await?;
                return Ok(());
            }
            "VRFY" | "EXPN" => {
                write_reply(&mut stream.inner, "252 2.5.2 Cannot VRFY user\r\n").await?;
            }
            "HELP" => {
                write_reply(
                    &mut stream.inner,
                    "214 2.0.0 Commands: EHLO HELO AUTH MAIL RCPT DATA RSET NOOP QUIT\r\n",
                )
                .await?;
            }
            _ => {
                write_reply(&mut stream.inner, "500 5.5.2 Unrecognized command\r\n").await?;
            }
        }
    }
}

fn finish_auth(state: &mut ConnState, user: String) {
    state.authenticated = true;
    state.auth_phase = None;
    tracing::debug!(user = %user, "SMTP client authenticated");
}

/// Common checks for MAIL/RCPT/DATA.
async fn require_ready<S: AsyncWrite + Unpin>(stream: &mut S, state: &ConnState) -> Result<bool> {
    if !state.ehlo {
        write_reply(stream, "503 5.5.1 Bad sequence of commands\r\n").await?;
        return Ok(false);
    }
    if !state.authenticated {
        write_reply(stream, "530 5.7.0 Authentication required\r\n").await?;
        return Ok(false);
    }
    Ok(true)
}

fn ehlo_reply(session: &Session, tls_active: bool) -> String {
    let mut reply = format!("250-{}\r\n", session.hostname);
    reply.push_str("250-8BITMIME\r\n");
    reply.push_str("250-PIPELINING\r\n");
    reply.push_str(&format!("250-SIZE {}\r\n", session.max_message_size));
    if session.tls.is_some() && !tls_active {
        reply.push_str("250-STARTTLS\r\n");
    }
    // Only advertise AUTH when it can actually succeed: over TLS, or when
    // the operator opted into plaintext authentication.
    if !session.users.is_empty() && (tls_active || session.allow_auth_insecure) {
        reply.push_str("250-AUTH PLAIN LOGIN\r\n");
    }
    reply.push_str("250 OK\r\n");
    reply
}

/// Parse `FROM:<addr>` / `TO:<addr>` style arguments.
fn parse_path_address(arg: Option<&str>) -> Option<String> {
    let arg = arg?.trim();
    if arg.is_empty() {
        return None;
    }
    let (_, rest) = arg.split_once(':')?;
    let rest = rest.trim();
    let addr = if let Some(start) = rest.find('<') {
        let end = rest[start + 1..].find('>')? + start + 1;
        &rest[start + 1..end]
    } else {
        // Lenient no-bracket form; stop at ESMTP parameters (SIZE=, BODY=, ...)
        match rest.split_once(char::is_whitespace) {
            Some((addr, _params)) => addr,
            None => rest,
        }
    };
    let addr = addr.trim().to_string();
    Some(addr)
}

/// Extract the `SIZE=<n>` ESMTP parameter from a MAIL argument, if present.
fn declared_size(arg: Option<&str>) -> Option<usize> {
    let arg = arg?;
    let idx = arg.to_ascii_uppercase().find("SIZE=")?;
    let value = arg[idx + "SIZE=".len()..]
        .split_whitespace()
        .next()?
        .parse::<usize>()
        .ok()?;
    Some(value)
}

async fn write_reply<S: AsyncWrite + Unpin>(stream: &mut S, reply: &str) -> Result<()> {
    stream.write_all(reply.as_bytes()).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Buffered line/block reader
// ---------------------------------------------------------------------------

struct StreamBuf<S> {
    inner: S,
    buf: Vec<u8>,
    pos: usize,
}

impl<S> StreamBuf<S> {
    fn new(inner: S) -> Self {
        StreamBuf {
            inner,
            buf: Vec::new(),
            pos: 0,
        }
    }

    fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> StreamBuf<S> {
    /// Read more bytes from the stream into the buffer. Returns false on EOF.
    async fn read_more(&mut self) -> std::io::Result<bool> {
        if self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        }
        let mut chunk = [0u8; 8192];
        let n = self.inner.read(&mut chunk).await?;
        if n == 0 {
            return Ok(false);
        }
        self.buf.extend_from_slice(&chunk[..n]);
        Ok(true)
    }

    /// Read one command line (without trailing CR/LF). Returns None on EOF.
    async fn read_line(&mut self, max_len: usize) -> std::io::Result<Option<Vec<u8>>> {
        loop {
            if let Some(rel) = self.buf[self.pos..].iter().position(|b| *b == b'\n') {
                let end = self.pos + rel;
                let mut line = self.buf[self.pos..end].to_vec();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                self.pos = end + 1;
                return Ok(Some(line));
            }
            if self.buf.len() - self.pos > max_len {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "command line too long",
                ));
            }
            if !self.read_more().await? {
                return Ok(None);
            }
        }
    }

    /// Read the DATA block up to the terminating dot line, de-stuffing dots.
    /// Returns None on EOF before the terminator.
    async fn read_data(&mut self, max_size: usize) -> std::io::Result<Option<Vec<u8>>> {
        let mut data = Vec::new();
        // One past the last byte of `data` already scanned for a terminator.
        // Scanning resumes a few bytes earlier so a terminator split across
        // two reads (or followed by pipelined bytes in the same segment) is
        // still found.
        let mut scanned = 0usize;
        const OVERLAP: usize = DATA_TERM.len() - 1;
        loop {
            // Drain whatever is buffered into `data` first, so a terminator
            // that arrived with the previous `read_more` is found.
            if self.pos < self.buf.len() {
                data.extend_from_slice(&self.buf[self.pos..]);
                self.pos = self.buf.len();
            }
            if let Some(idx) = find_terminator(&data, scanned.saturating_sub(OVERLAP)) {
                let body = data[..idx].to_vec();
                return Ok(Some(unstuff(&body)));
            }
            scanned = data.len();
            if data.len() > max_size {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "message too large",
                ));
            }
            if !self.read_more().await? {
                return Ok(None);
            }
        }
    }
}

/// Locate the DATA terminator line (a line containing only a dot) at or after
/// `from`. Returns the index of the dot, so the message body is `data[..idx]`
/// (which keeps the CRLF ending the final content line).
fn find_terminator(data: &[u8], from: usize) -> Option<usize> {
    let start = from.min(data.len());
    let mut i = start;
    while i + DATA_TERM.len() <= data.len() {
        if data[i..i + DATA_TERM.len()] == *DATA_TERM {
            return Some(i + 2);
        }
        i += 1;
    }
    // lenient: "\n.\n"
    let mut j = start;
    while j + DATA_TERM_LF.len() <= data.len() {
        if data[j..j + DATA_TERM_LF.len()] == *DATA_TERM_LF {
            return Some(j + 1);
        }
        j += 1;
    }
    None
}

/// Reverse dot-stuffing: remove the extra dot from lines that begin with
/// a dot (RFC 5321), including the first line of the message body.
fn unstuff(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len());
    let mut i = 0;
    while i < body.len() {
        let at_line_start = i == 0 || body[i - 1] == b'\n';
        if at_line_start && body[i] == b'.' && i + 1 < body.len() && body[i + 1] == b'.' {
            out.push(b'.');
            i += 2;
        } else {
            out.push(body[i]);
            i += 1;
        }
    }
    out
}

fn load_tls_acceptor(cert_path: &Path, key_path: &Path) -> Result<TlsAcceptor> {
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut std::io::BufReader::new(
        std::fs::File::open(cert_path).map_err(|e| {
            crate::error::Error::Config(format!("cannot read cert {}: {e}", cert_path.display()))
        })?,
    ))
    .collect::<std::result::Result<_, _>>()
    .map_err(|e| {
        crate::error::Error::Config(format!("cannot parse cert {}: {e}", cert_path.display()))
    })?;

    if certs.is_empty() {
        return Err(crate::error::Error::Config(format!(
            "no certificates found in {}",
            cert_path.display()
        )));
    }

    let key_der = PrivateKeyDer::from_pem_file(key_path).map_err(|e| {
        crate::error::Error::Config(format!("cannot parse key {}: {e}", key_path.display()))
    })?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key_der)
        .map_err(|e| crate::error::Error::Tls(e.to_string()))?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_path_address() {
        assert_eq!(
            parse_path_address(Some("FROM:<a@b.com>")),
            Some("a@b.com".to_string())
        );
        assert_eq!(
            parse_path_address(Some("FROM: <a@b.com> SIZE=1000")),
            Some("a@b.com".to_string())
        );
        assert_eq!(
            parse_path_address(Some("TO:jane@example.com")),
            Some("jane@example.com".to_string())
        );
        assert_eq!(
            parse_path_address(Some("FROM:a@b.com SIZE=1000 BODY=8BITMIME")),
            Some("a@b.com".to_string())
        );
        assert_eq!(parse_path_address(None), None);
    }

    #[test]
    fn ehlo_capabilities() {
        let session = Session {
            hostname: "mx.example.com".into(),
            users: vec![SmtpUser {
                username: "u".into(),
                password: "p".into(),
            }],
            max_message_size: 1000,
            max_recipients: 10,
            spool: crate::queue::Spool::open(std::env::temp_dir().join("mm-test-spool"))
                .unwrap()
                .0,
            tls: None,
            allow_auth_insecure: false,
        };
        let reply = ehlo_reply(&session, false);
        assert!(reply.contains("250-mx.example.com"));
        // No TLS and insecure auth disabled: AUTH must not be advertised.
        assert!(!reply.contains("AUTH"));
        assert!(!reply.contains("STARTTLS"));
        assert!(reply.contains("250-SIZE 1000"));

        let reply_insecure = ehlo_reply(
            &Session {
                allow_auth_insecure: true,
                ..session
            },
            false,
        );
        assert!(reply_insecure.contains("250-AUTH PLAIN LOGIN"));
    }

    #[test]
    fn parses_declared_size() {
        assert_eq!(declared_size(Some("FROM:<a@b.com> SIZE=1000")), Some(1000));
        assert_eq!(declared_size(Some("FROM:a@b.com size=42")), Some(42));
        assert_eq!(declared_size(Some("FROM:<a@b.com> BODY=8BITMIME")), None);
        assert_eq!(declared_size(Some("FROM:<a@b.com> SIZE=abc")), None);
        assert_eq!(declared_size(None), None);
    }

    #[test]
    fn detects_data_terminators() {
        let data = b"From: a\r\n\r\nbody\r\n.\r\nmore";
        assert_eq!(find_terminator(data, 0), Some(17));
        let data2 = b"hello\n.\nworld";
        assert_eq!(find_terminator(data2, 0), Some(6));
        assert_eq!(find_terminator(b"no terminator here", 0), None);
    }

    #[test]
    fn un_stuffs_dots() {
        assert_eq!(unstuff(b"a\r\n..\r\nb"), b"a\r\n.\r\nb");
        assert_eq!(unstuff(b"..line"), b".line");
        assert_eq!(unstuff(b"hello..world"), b"hello..world");
        assert_eq!(unstuff(b"no dots"), b"no dots");
    }

    #[tokio::test]
    async fn stream_reads_lines_and_data() {
        use tokio::io::duplex;

        let (mut client, server) = duplex(1024);
        let handle = tokio::spawn(async move {
            let mut buf = StreamBuf::new(server);
            let line = buf.read_line(512).await.unwrap().unwrap();
            let data = buf.read_data(1024).await.unwrap().unwrap();
            (line, data)
        });

        client
            .write_all(
                b"EHLO example.com\r\nFrom: a@b.com\r\nTo: c@d.com\r\n\r\n..stuffed\r\n.\r\n",
            )
            .await
            .unwrap();
        client.shutdown().await.unwrap();

        let (line, data) = handle.await.unwrap();
        assert_eq!(line, b"EHLO example.com");
        assert_eq!(data, b"From: a@b.com\r\nTo: c@d.com\r\n\r\n.stuffed\r\n");
    }

    #[tokio::test]
    async fn stream_finds_terminator_before_pipelined_bytes() {
        use tokio::io::duplex;

        // The terminator is followed by further bytes in the same TCP segment
        // (e.g. a pipelined QUIT); it must still be detected.
        let (mut client, server) = duplex(1024);
        let handle = tokio::spawn(async move {
            let mut buf = StreamBuf::new(server);
            buf.read_data(1024).await.unwrap().unwrap()
        });

        client
            .write_all(b"From: a@b.com\r\n\r\nbody\r\n.\r\nQUIT\r\n")
            .await
            .unwrap();
        client.shutdown().await.unwrap();

        assert_eq!(handle.await.unwrap(), b"From: a@b.com\r\n\r\nbody\r\n");
    }
}
