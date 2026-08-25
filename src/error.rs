use std::fmt;

/// Unified error type for micromail.
#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Config(String),
    Dkim(String),
    Spool(String),
    Send(String),
    Smtp(String),
    Dns(String),
    Tls(String),
    InvalidInput(String),
    /// Some recipients were delivered successfully before the failure.
    /// Retry logic must only re-send `remaining`, never `delivered`.
    PartialDelivery {
        delivered: Vec<String>,
        remaining: Vec<String>,
        source: Box<Error>,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::Config(e) => write!(f, "config error: {e}"),
            Error::Dkim(e) => write!(f, "dkim error: {e}"),
            Error::Spool(e) => write!(f, "spool error: {e}"),
            Error::Send(e) => write!(f, "send error: {e}"),
            Error::Smtp(e) => write!(f, "smtp error: {e}"),
            Error::Dns(e) => write!(f, "dns error: {e}"),
            Error::Tls(e) => write!(f, "tls error: {e}"),
            Error::InvalidInput(e) => write!(f, "invalid input: {e}"),
            Error::PartialDelivery {
                delivered,
                remaining,
                source,
            } => write!(
                f,
                "partial delivery: {} recipient(s) delivered, {} remaining: {source}",
                delivered.len(),
                remaining.len()
            ),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<mail_send::Error> for Error {
    fn from(e: mail_send::Error) -> Self {
        Error::Send(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
