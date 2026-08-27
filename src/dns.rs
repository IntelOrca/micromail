//! DNS record rendering and SPF policy construction for the `dns` command.

use crate::error::{Error, Result};

/// Output format for rendered DNS records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum DnsFormat {
    /// Human-readable blocks: `Name:`, `Type:`, `Content:`.
    Human,
    /// Ready-to-paste BIND zone lines: `<name> IN TXT "<content>"`.
    Bind,
}

/// Render one TXT record.
pub fn render_record(name: &str, content: &str, format: DnsFormat) -> String {
    match format {
        DnsFormat::Human => format!("Name: {name}\nType: TXT\nContent: {content}\n"),
        DnsFormat::Bind => {
            // DNS TXT string literals are capped at 255 bytes; longer values
            // (e.g. RSA DKIM keys) must be split into concatenated chunks.
            let chunks: Vec<String> = content
                .as_bytes()
                .chunks(255)
                .map(|chunk| format!("\"{}\"", String::from_utf8_lossy(chunk)))
                .collect();
            format!("{name} IN TXT {}\n", chunks.join(" "))
        }
    }
}

/// Build an SPF TXT record value for `domain`.
///
/// The policy always begins with `v=spf1` and ends with `~all`. When the
/// config `hostname` is set (and not `localhost`) an `a:<hostname>` mechanism
/// is added, plus `mx`. Explicit `--ip` addresses contribute `ip4:`/`ip6:`
/// mechanisms. `--auto-ip` attempts to discover this server's public address;
/// if no concrete address is known (no `--ip` and auto-detection unavailable),
/// a placeholder `ip4:<IPV4>` is emitted so the operator knows to fill it in.
pub fn build_spf(
    domain: &str,
    hostname: &str,
    ips: &[String],
    includes: &[String],
    auto_ip: bool,
) -> Result<String> {
    let _ = domain;
    let mut parts: Vec<String> = vec!["v=spf1".to_string()];

    if !hostname.is_empty() && hostname != "localhost" {
        parts.push(format!("a:{hostname}"));
    }
    parts.push("mx".to_string());

    let mut has_concrete_ip = false;
    for ip in ips {
        let ip = ip.trim();
        if ip.is_empty() {
            continue;
        }
        if ip.contains(':') {
            parts.push(format!("ip6:{ip}"));
        } else {
            parts.push(format!("ip4:{ip}"));
        }
        has_concrete_ip = true;
    }

    if auto_ip {
        match fetch_public_ip() {
            Ok(Some(ip)) => {
                if ip.contains(':') {
                    parts.push(format!("ip6:{ip}"));
                } else {
                    parts.push(format!("ip4:{ip}"));
                }
                has_concrete_ip = true;
            }
            Ok(None) => {
                eprintln!("dns: auto-ip lookup returned no address; using placeholder");
            }
            Err(e) => {
                eprintln!("dns: auto-ip lookup failed ({e}); using placeholder");
            }
        }
    }

    if !has_concrete_ip {
        parts.push("ip4:<IPV4>".to_string());
    }

    for inc in includes {
        let inc = inc.trim();
        if !inc.is_empty() {
            parts.push(format!("include:{inc}"));
        }
    }

    parts.push("~all".to_string());
    Ok(parts.join(" "))
}

/// Discover this host's public IPv4/IPv6 address via an echo service.
///
/// Blocking by design (the `dns` command runs synchronously). Fails cleanly so
/// the caller can fall back to a placeholder.
fn fetch_public_ip() -> Result<Option<String>> {
    let resp = ureq::get("https://api.ipify.org")
        .call()
        .map_err(|e| Error::Dns(format!("auto-ip request failed: {e}")))?;
    let body = resp
        .into_string()
        .map_err(|e| Error::Dns(format!("auto-ip read failed: {e}")))?;
    let ip = body.trim().to_string();
    if ip.is_empty() {
        Ok(None)
    } else {
        Ok(Some(ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_human_and_bind() {
        assert_eq!(
            render_record("x", "v=DKIM1", DnsFormat::Human),
            "Name: x\nType: TXT\nContent: v=DKIM1\n"
        );
        assert_eq!(
            render_record("x", "v=DKIM1", DnsFormat::Bind),
            "x IN TXT \"v=DKIM1\"\n"
        );
    }

    #[test]
    fn bind_chunks_long_txt() {
        let content = "a".repeat(600);
        let out = render_record("x", &content, DnsFormat::Bind);
        // Three concatenated quoted strings, each <= 255 bytes.
        let quoted: Vec<&str> = out
            .trim_end()
            .trim_start_matches("x IN TXT ")
            .split(' ')
            .collect();
        assert_eq!(quoted.len(), 3, "{out}");
        for q in &quoted {
            assert!(q.starts_with('"') && q.ends_with('"'), "{q}");
            assert!(q.len() - 2 <= 255, "chunk too long: {q}");
        }
        // Reassembling the chunks must reproduce the original content.
        let joined: String = quoted.iter().map(|q| &q[1..q.len() - 1]).collect();
        assert_eq!(joined, content);
    }

    #[test]
    fn spf_with_placeholder_when_no_ip() {
        let spf = build_spf("example.com", "localhost", &[], &[], false).unwrap();
        assert!(spf.starts_with("v=spf1 mx"), "{spf}");
        assert!(spf.ends_with("~all"), "{spf}");
        assert!(spf.contains("ip4:<IPV4>"), "{spf}");
    }

    #[test]
    fn spf_with_hostname_and_ip_and_include() {
        let spf = build_spf(
            "example.com",
            "mail.example.com",
            &["1.2.3.4".into(), "2001:db8::1".into()],
            &["_spf.example.net".into()],
            false,
        )
        .unwrap();
        assert!(spf.contains("a:mail.example.com"), "{spf}");
        assert!(spf.contains("mx"), "{spf}");
        assert!(spf.contains("ip4:1.2.3.4"), "{spf}");
        assert!(spf.contains("ip6:2001:db8::1"), "{spf}");
        assert!(spf.contains("include:_spf.example.net"), "{spf}");
        assert!(!spf.contains("<IPV4>"), "{spf}");
    }
}
