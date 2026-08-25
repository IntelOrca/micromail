use crate::error::{Error, Result};
use mail_builder::MessageBuilder;

/// Structured outbound message used by both the REST API and the `send`
/// CLI subcommand.
#[derive(Debug, Clone, Default)]
pub struct Outgoing {
    pub from: String,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub subject: Option<String>,
    pub text: Option<String>,
    pub html: Option<String>,
}

/// Build the raw RFC 5322 message. `bcc` recipients are delivered via the
/// SMTP envelope only and never appear in the message headers.
pub fn build(out: &Outgoing) -> Result<Vec<u8>> {
    let mut builder = MessageBuilder::new().from(out.from.trim());
    if let Some(subject) = &out.subject {
        builder = builder.subject(subject);
    }
    for addr in &out.to {
        builder = builder.to(addr.trim());
    }
    for addr in &out.cc {
        builder = builder.cc(addr.trim());
    }
    if let Some(text) = &out.text {
        builder = builder.text_body(text);
    }
    if let Some(html) = &out.html {
        builder = builder.html_body(html);
    }
    builder
        .write_to_vec()
        .map_err(|e| Error::InvalidInput(format!("cannot build message: {e}")))
}

/// Validate a simple email address.
pub fn is_valid_email(addr: &str) -> bool {
    let addr = addr.trim();
    if addr.is_empty()
        || addr.len() > 320
        // Reject control characters (CR/LF/NUL, ...) so addresses can never
        // inject or corrupt SMTP command/header streams.
        || addr.chars().any(char::is_control)
        || addr.contains(' ')
        || addr.starts_with('@')
        || addr.starts_with('.')
    {
        return false;
    }
    let Some(at) = addr.find('@') else {
        return false;
    };
    if addr[at + 1..].contains('@') {
        return false;
    }
    let local = &addr[..at];
    let domain = &addr[at + 1..];
    !local.is_empty() && !domain.is_empty() && !domain.starts_with('.') && !domain.ends_with('.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_emails() {
        assert!(is_valid_email("user@example.com"));
        assert!(is_valid_email("user+tag@example.co.uk"));
        assert!(!is_valid_email(""));
        assert!(!is_valid_email("no-at-sign"));
        assert!(!is_valid_email("a@b@c.com"));
        assert!(!is_valid_email("a @b.com"));
        assert!(!is_valid_email("a@"));
        assert!(!is_valid_email("@b.com"));
        assert!(!is_valid_email("a@b."));
        assert!(!is_valid_email("a\nx@evil.com"));
        assert!(!is_valid_email("a\0@b.com"));
        assert!(!is_valid_email("a@b.com\r\nBcc: x@y.com"));
    }

    #[test]
    fn builds_without_bcc_header() {
        let out = Outgoing {
            from: "a@b.com".into(),
            to: vec!["c@d.com".into()],
            cc: vec![],
            bcc: vec!["e@f.com".into()],
            subject: Some("Hello".into()),
            text: Some("body".into()),
            html: None,
        };
        let body = build(&out).unwrap();
        let text = String::from_utf8(body).unwrap();
        assert!(text.contains("To: <c@d.com>"));
        assert!(text.contains("Subject: Hello"));
        assert!(!text.contains("e@f.com"));
        assert!(!text.contains("Bcc"));
    }

    #[test]
    fn builds_multipart_when_html_present() {
        let out = Outgoing {
            from: "a@b.com".into(),
            to: vec!["c@d.com".into()],
            cc: vec![],
            bcc: vec![],
            subject: Some("Hi".into()),
            text: Some("plain".into()),
            html: Some("<p>rich</p>".into()),
        };
        let body = build(&out).unwrap();
        let text = String::from_utf8(body).unwrap();
        assert!(text.contains("multipart/alternative"));
        assert!(text.contains("<p>rich</p>"));
    }
}
