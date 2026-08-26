use crate::error::{Error, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::pkcs8::DecodePrivateKey as EdDecodePrivateKey;
use ed25519_dalek::Signer as _;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey as RsaDecodePrivateKey;
use rsa::{Pkcs1v15Sign, RsaPrivateKey};
use rustls_pki_types::{pem::PemObject, PrivateKeyDer};
use sha1::Sha1;
use sha2::{Digest, Sha256};
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

#[derive(Debug)]
pub enum PrivateKey {
    Rsa(RsaPrivateKey),
    Ed25519(ed25519_dalek::SigningKey),
}

impl PrivateKey {
    pub fn is_rsa(&self) -> bool {
        matches!(self, PrivateKey::Rsa(_))
    }
    pub fn is_ed25519(&self) -> bool {
        matches!(self, PrivateKey::Ed25519(_))
    }
}

pub struct DkimEntry {
    pub domain: String,
    pub selector: String,
    pub key: PrivateKey,
}

/// Holds the DKIM keys discovered under `<config dir>/dkim/<domain>/<selector>`.
/// Each selector file's name is the selector and its contents are the PEM private key.
/// Strict: no legacy `key.pem+selector` file, group/other perms `0o077` rejected.
pub struct DkimManager {
    entries: HashMap<String, HashMap<String, DkimEntry>>,
    default_selector: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DkimAlgorithm {
    RsaSha256,
    RsaSha1,
    Ed25519Sha256,
}

impl DkimAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            DkimAlgorithm::RsaSha256 => "rsa-sha256",
            DkimAlgorithm::RsaSha1 => "rsa-sha1",
            DkimAlgorithm::Ed25519Sha256 => "ed25519-sha256",
        }
    }
}

pub struct DkimSigner {
    pub domain: String,
    pub selector: String,
    pub headers: Vec<String>,
    key: PrivateKey,
    algorithm: DkimAlgorithm,
}

impl DkimSigner {
    pub fn algorithm(&self) -> DkimAlgorithm {
        self.algorithm
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub fn selector(&self) -> &str {
        &self.selector
    }

    /// Sign `message` and return the full `DKIM-Signature:` header line (without trailing CRLF).
    pub fn sign(&self, message: &[u8]) -> Result<String> {
        self.sign_with_algorithm(message, self.algorithm)
    }

    pub fn sign_with_algorithm(&self, message: &[u8], algo: DkimAlgorithm) -> Result<String> {
        // Validate algorithm matches key type
        match (&self.key, algo) {
            (PrivateKey::Rsa(_), DkimAlgorithm::Ed25519Sha256) => {
                return Err(Error::Dkim("Ed25519 algorithm requires Ed25519 key".into()))
            }
            (PrivateKey::Ed25519(_), DkimAlgorithm::RsaSha256)
            | (PrivateKey::Ed25519(_), DkimAlgorithm::RsaSha1) => {
                return Err(Error::Dkim("RSA algorithm requires RSA key".into()))
            }
            _ => {}
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.sign_with_time(message, algo, now)
    }

    pub fn sign_with_time(&self, message: &[u8], algo: DkimAlgorithm, now: u64) -> Result<String> {
        let mut iter = HeaderIterator::new(message);
        let mut parsed_headers = Vec::new();
        for (name, value) in iter.by_ref() {
            parsed_headers.push((name, value));
        }
        let body = iter.body();

        // Collect every occurrence of each requested header, then sign them in
        // reverse message order (RFC 6376 5.4.2 bottom-up selection semantics,
        // matching mail-auth's canonicalize + CanonicalHeaders::rev()).
        let mut occurrences: Vec<(usize, String, &[u8], &[u8])> = Vec::new();
        for want in &self.headers {
            for (pos, (name, value)) in parsed_headers.iter().enumerate() {
                if name.eq_ignore_ascii_case(want.as_bytes()) {
                    occurrences.push((
                        pos,
                        String::from_utf8_lossy(name).into_owned(),
                        *name,
                        *value,
                    ));
                }
            }
        }
        if occurrences.is_empty() {
            return Err(Error::Dkim("no signable headers found".into()));
        }
        occurrences.sort_by_key(|(pos, _, _, _)| std::cmp::Reverse(*pos));

        let signed_header_names: Vec<String> = occurrences
            .iter()
            .map(|(_, name, _, _)| name.clone())
            .collect();
        let mut signed_headers_canonical = Vec::new();
        for (_, _, name, value) in &occurrences {
            relaxed_canonicalize_header(name, value, &mut signed_headers_canonical);
        }
        let bh = compute_body_hash(body, algo)?;

        // Data hash input per RFC 6376 3.7: canonicalized h= headers (each
        // CRLF-terminated), then the DKIM-Signature header with an empty b=
        // value and NO trailing CRLF.
        let mut signed_data = signed_headers_canonical;
        self.write_signature(&mut signed_data, false, &signed_header_names, now, &bh, "");

        let signature_bytes = match (&self.key, algo) {
            (PrivateKey::Rsa(k), DkimAlgorithm::RsaSha256) => {
                let hash = Sha256::digest(&signed_data);
                k.sign(pkcs1v15_sha256(), &hash)
                    .map_err(|e| Error::Dkim(format!("RSA sign failed: {e}")))?
            }
            (PrivateKey::Rsa(k), DkimAlgorithm::RsaSha1) => {
                let hash = Sha1::digest(&signed_data);
                k.sign(pkcs1v15_sha1(), &hash)
                    .map_err(|e| Error::Dkim(format!("RSA sign failed: {e}")))?
            }
            (PrivateKey::Ed25519(k), DkimAlgorithm::Ed25519Sha256) => {
                let hash = Sha256::digest(&signed_data);
                k.sign(&hash).to_bytes().to_vec()
            }
            _ => unreachable!(),
        };

        let b = BASE64.encode(&signature_bytes);

        // Transmitted header form (folded with CRLF+WSP, trailing ';').
        // The trailing CRLF is stripped because insert_dkim_header splices the
        // header ahead of the message's existing "\r\n\r\n".
        let mut final_header = Vec::with_capacity(signed_data.len());
        self.write_signature(&mut final_header, true, &signed_header_names, now, &bh, &b);
        debug_assert!(final_header.ends_with(b"\r\n"));
        final_header.truncate(final_header.len() - 2);

        Ok(String::from_utf8_lossy(&final_header).into_owned())
    }

    /// Byte-exact port of mail-auth's `Signature::write`
    /// (patches/mail-auth/src/dkim/headers.rs @ bd89ed6).
    ///
    /// `as_header = false` renders the form used as data-hash input under
    /// relaxed header canonicalization: lowercase `dkim-signature:` prefix,
    /// fold token = single SP, and no trailing newline.
    /// `as_header = true` renders the transmitted header: `DKIM-Signature: `
    /// prefix, fold token `\r\n\t`, terminated by `;\r\n`.
    fn write_signature(
        &self,
        writer: &mut Vec<u8>,
        as_header: bool,
        h: &[String],
        t: u64,
        bh: &str,
        b: &str,
    ) {
        let (header, new_line): (&[u8], &[u8]) = if as_header {
            (b"DKIM-Signature: ", b"\r\n\t")
        } else {
            (b"dkim-signature:", b" ")
        };
        writer.extend_from_slice(header);
        writer.extend_from_slice(b"v=1; a=");
        writer.extend_from_slice(self.algorithm.as_str().as_bytes());
        for (tag, value) in [
            (&b"; s="[..], self.selector.as_bytes()),
            (&b"; d="[..], self.domain.as_bytes()),
        ] {
            writer.extend_from_slice(tag);
            writer.extend_from_slice(value);
        }
        writer.extend_from_slice(b"; c=");
        writer.extend_from_slice(b"relaxed");
        writer.extend_from_slice(b"/");
        writer.extend_from_slice(b"relaxed");

        writer.extend_from_slice(b";");
        writer.extend_from_slice(new_line);

        let mut bw = 1;
        for (num, hdr) in h.iter().enumerate() {
            if bw + hdr.len() + 1 >= 76 {
                writer.extend_from_slice(new_line);
                bw = 1;
            }
            if num > 0 {
                write_len(writer, b":", &mut bw);
            } else {
                write_len(writer, b"h=", &mut bw);
            }
            write_len(writer, hdr.as_bytes(), &mut bw);
        }

        if t > 0 {
            let value = t.to_string();
            write_len(writer, b";", &mut bw);
            if bw + b"t=".len() + value.len() >= 76 {
                writer.extend_from_slice(new_line);
                bw = 1;
            } else {
                write_len(writer, b" ", &mut bw);
            }
            write_len(writer, b"t=", &mut bw);
            write_len(writer, value.as_bytes(), &mut bw);
        }

        for (tag, value) in [(&b"; bh="[..], bh), (&b"; b="[..], b)] {
            write_len(writer, tag, &mut bw);
            for &byte in value.as_bytes() {
                write_len(writer, &[byte], &mut bw);
                if bw >= 76 {
                    writer.extend_from_slice(new_line);
                    bw = 1;
                }
            }
        }

        writer.extend_from_slice(b";");
        if as_header {
            writer.extend_from_slice(b"\r\n");
        }
    }
}

fn write_len(writer: &mut Vec<u8>, buf: &[u8], len: &mut usize) {
    writer.extend_from_slice(buf);
    *len += buf.len();
}

fn pkcs1v15_sha256() -> Pkcs1v15Sign {
    const SHA256_PREFIX: &[u8] = &[
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    Pkcs1v15Sign {
        hash_len: Some(32),
        prefix: SHA256_PREFIX.into(),
    }
}

fn pkcs1v15_sha1() -> Pkcs1v15Sign {
    const SHA1_PREFIX: &[u8] = &[
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
    ];
    Pkcs1v15Sign {
        hash_len: Some(20),
        prefix: SHA1_PREFIX.into(),
    }
}

fn compute_body_hash(body: &[u8], algo: DkimAlgorithm) -> Result<String> {
    let mut canonical = Vec::new();
    relaxed_canonicalize_body(body, &mut canonical);
    let hash_bytes: Vec<u8> = match algo {
        DkimAlgorithm::RsaSha256 | DkimAlgorithm::Ed25519Sha256 => {
            Sha256::digest(&canonical).to_vec()
        }
        DkimAlgorithm::RsaSha1 => Sha1::digest(&canonical).to_vec(),
    };
    Ok(BASE64.encode(&hash_bytes))
}

fn relaxed_canonicalize_header(name: &[u8], value: &[u8], out: &mut Vec<u8>) {
    // Name: lowercased, WSP removed, then ":"
    for &ch in name {
        if !ch.is_ascii_whitespace() {
            out.push(ch.to_ascii_lowercase());
        }
    }
    out.push(b':');
    // Value: unfold (drop CR/LF), compress WSP runs to a single SP, trim
    // leading/trailing WSP, then terminate with CRLF. Mirrors mail-auth's
    // canonicalize_headers relaxed branch.
    let mut tmp = Vec::new();
    let mut bw_tmp = 0usize;
    let mut last_ch = 0u8;
    for &ch in value {
        if !ch.is_ascii_whitespace() {
            // Compress runs of WSP to a single SP, but only when the previous
            // character was an actual space/tab (mail-auth parity; a bare CR
            // or LF inside the value does not produce a SP).
            if (last_ch == b' ' || last_ch == b'\t') && bw_tmp > 0 {
                tmp.push(b' ');
            }
            tmp.push(ch);
            bw_tmp += 1;
        }
        last_ch = ch;
    }
    out.extend_from_slice(&tmp);
    out.extend_from_slice(b"\r\n");
}

fn relaxed_canonicalize_body(body: &[u8], out: &mut Vec<u8>) {
    // Relaxed body canonicalization:
    // - Remove trailing WSP at end of each line, compress WSP within line to single SP, remove empty lines at end?
    // - Actually spec relaxed body: remove trailing WSP, compress WSP, ensure lines end with CRLF, remove trailing empty lines, ensure body ends with CRLF if not empty, else empty.
    // We can copy mail-auth's CanonicalBody relaxed logic.

    if body.is_empty() {
        return;
    }

    let mut last_ch: u8 = 0;
    let mut crlf_seq: usize = 0;
    let mut is_empty = true;

    for &ch in body {
        match ch {
            b' ' | b'\t' => {
                while crlf_seq > 0 {
                    out.extend_from_slice(b"\r\n");
                    crlf_seq -= 1;
                }
                is_empty = false;
                // don't write yet, wait for next non-WSP to decide if we need SP
                // But we need to track that we have pending WSP
                // Actually we need to defer writing WSP until next non-WSP
                // So we set last_ch to WSP and continue
            }
            b'\n' => {
                crlf_seq += 1;
            }
            b'\r' => {}
            _ => {
                while crlf_seq > 0 {
                    out.extend_from_slice(b"\r\n");
                    crlf_seq -= 1;
                }
                if last_ch == b' ' || last_ch == b'\t' {
                    out.push(b' ');
                }
                out.push(ch);
                is_empty = false;
            }
        }
        last_ch = ch;
    }

    if !is_empty {
        out.extend_from_slice(b"\r\n");
    }
}

// HeaderIterator copied from mail-auth common/headers
struct HeaderIterator<'x> {
    message: &'x [u8],
    iter: std::iter::Peekable<std::iter::Enumerate<std::slice::Iter<'x, u8>>>,
    start_pos: usize,
}

impl<'x> HeaderIterator<'x> {
    fn new(message: &'x [u8]) -> Self {
        HeaderIterator {
            message,
            iter: message.iter().enumerate().peekable(),
            start_pos: 0,
        }
    }

    fn body(&self) -> &[u8] {
        let body = self.message.get(self.start_pos..).unwrap_or_default();
        if body.starts_with(b"\r\n") {
            &body[2..]
        } else if body.starts_with(b"\n") {
            &body[1..]
        } else {
            body
        }
    }
}

impl<'x> Iterator for HeaderIterator<'x> {
    type Item = (&'x [u8], &'x [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let mut colon_pos = usize::MAX;
        let mut last_ch = 0;

        while let Some((pos, &ch)) = self.iter.next() {
            if colon_pos == usize::MAX {
                match ch {
                    b':' => {
                        colon_pos = pos;
                    }
                    b'\n' => {
                        if last_ch == b'\r' || self.start_pos == pos {
                            return None;
                        } else if self
                            .iter
                            .peek()
                            .is_none_or(|(_, next_byte)| !b" \t".contains(*next_byte))
                        {
                            let header_name = self
                                .message
                                .get(self.start_pos..pos + 1)
                                .unwrap_or_default();
                            self.start_pos = pos + 1;
                            return Some((header_name, b""));
                        }
                    }
                    _ => (),
                }
            } else if ch == b'\n'
                && self
                    .iter
                    .peek()
                    .is_none_or(|(_, next_byte)| !b" \t".contains(*next_byte))
            {
                let header_name = self
                    .message
                    .get(self.start_pos..colon_pos)
                    .unwrap_or_default();
                let header_value = self.message.get(colon_pos + 1..pos + 1).unwrap_or_default();

                self.start_pos = pos + 1;

                return Some((header_name, header_value));
            }

            last_ch = ch;
        }

        None
    }
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
                let key = parse_key(&key_pem).map_err(|e| {
                    Error::Config(format!(
                        "invalid DKIM key {} (selector {}): {e}",
                        path.display(),
                        selector
                    ))
                })?;

                let inner = entries.entry(domain.clone()).or_default();
                inner.insert(
                    selector.clone(),
                    DkimEntry {
                        domain: domain.clone(),
                        selector: selector.clone(),
                        key,
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
        self.entries
            .get(domain)
            .map(|m| !m.is_empty())
            .unwrap_or(false)
    }

    /// Build a ready-to-use DKIM signer for `domain`, signing the given
    /// `headers` (they should be a subset of the headers present in the
    /// message being signed). Selects selector via default_selector if present,
    /// else if exactly one selector exists uses it, otherwise fails.
    pub fn build_signer(&self, domain: &str, headers: &[&str]) -> Result<DkimSigner> {
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

        // Decide algorithm based on key type; default RSA->Sha256, Ed25519->Sha256
        let algorithm = match &entry.key {
            PrivateKey::Rsa(_) => DkimAlgorithm::RsaSha256,
            PrivateKey::Ed25519(_) => DkimAlgorithm::Ed25519Sha256,
        };

        // Clone key for signer (need to move out, so we need to handle ownership)
        // We can't move out of entry, so we need to clone the key
        let key_clone = match &entry.key {
            PrivateKey::Rsa(k) => PrivateKey::Rsa(k.clone()),
            PrivateKey::Ed25519(k) => {
                // ed25519_dalek::SigningKey doesn't impl Clone? It does
                PrivateKey::Ed25519(ed25519_dalek::SigningKey::from_bytes(&k.to_bytes()))
            }
        };

        Ok(DkimSigner {
            domain: entry.domain.clone(),
            selector: entry.selector.clone(),
            headers: headers.iter().map(|h| h.to_string()).collect(),
            key: key_clone,
            algorithm,
        })
    }

    pub fn default_selector(&self) -> &str {
        &self.default_selector
    }
}

fn is_valid_selector(s: &str) -> bool {
    if s.is_empty() || s.len() > 63 {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Parse a PEM private key into a DKIM signing key, accepting RSA (PKCS1 or
/// PKCS8) and Ed25519 (PKCS8). Allows 1024-bit RSA.
fn parse_key(pem: &[u8]) -> Result<PrivateKey> {
    let der = PrivateKeyDer::from_pem_slice(pem)
        .map_err(|e| Error::Dkim(format!("cannot parse private key PEM: {e}")))?;
    match der {
        PrivateKeyDer::Pkcs1(d) => {
            let k = RsaPrivateKey::from_pkcs1_der(d.secret_pkcs1_der())
                .map_err(|e| Error::Dkim(format!("invalid RSA PKCS1 key: {e}")))?;
            Ok(PrivateKey::Rsa(k))
        }
        PrivateKeyDer::Pkcs8(d) => {
            let bytes = d.secret_pkcs8_der().to_vec();
            // Try RSA first
            if let Ok(k) = RsaPrivateKey::from_pkcs8_der(&bytes) {
                return Ok(PrivateKey::Rsa(k));
            }
            // Try Ed25519
            if let Ok(k) = ed25519_dalek::SigningKey::from_pkcs8_der(&bytes) {
                return Ok(PrivateKey::Ed25519(k));
            }
            Err(Error::Dkim(
                "unsupported private key format for DKIM; use RSA or Ed25519".into(),
            ))
        }
        PrivateKeyDer::Sec1(_) => Err(Error::Dkim(
            "unsupported private key format for DKIM; use RSA or Ed25519".into(),
        )),
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
        #[cfg(not(unix))]
        let _ = mode;
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
        assert!(matches!(key, PrivateKey::Rsa(_)));
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
        let _ = signer;
    }

    #[test]
    fn single_selector_fallback_when_default_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let domain_dir = dir.path().join("dkim/example.com");
        std::fs::create_dir_all(&domain_dir).unwrap();
        write_key(&domain_dir.join("onlyone"), 0o600);
        let mgr = DkimManager::load(&dir.path().join("dkim"), "default").unwrap();
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
        write_key(&usr_dom.join("default"), 0o600);
        write_key(&usr_dom.join("extra"), 0o600);
        let mgr = DkimManager::load_merged(
            &sys.path().join("dkim"),
            &usr.path().join("dkim"),
            "default",
        )
        .unwrap();
        assert_eq!(mgr.len(), 2);
        drop(sys);
        drop(usr);
    }

    #[test]
    fn signs_rsa_sha256() {
        let key = parse_key(RSA_KEY.as_bytes()).unwrap();
        let signer = DkimSigner {
            domain: "example.com".into(),
            selector: "mail2026".into(),
            headers: vec!["From".into(), "To".into(), "Subject".into()],
            key,
            algorithm: DkimAlgorithm::RsaSha256,
        };
        let msg = b"From: a@example.com\r\nTo: b@example.com\r\nSubject: Hi\r\n\r\nbody\r\n";
        let header = signer.sign(msg).unwrap();
        assert!(header.starts_with("DKIM-Signature:"));
        assert!(header.contains("a=rsa-sha256"));
        assert!(header.contains("d=example.com"));
        assert!(header.contains("s=mail2026"));
        assert!(header.contains("bh="));
        assert!(header.contains("b="));
    }

    #[test]
    fn signs_rsa_sha1() {
        let key = parse_key(RSA_KEY.as_bytes()).unwrap();
        let signer = DkimSigner {
            domain: "example.com".into(),
            selector: "mail2026".into(),
            headers: vec!["From".into()],
            key,
            algorithm: DkimAlgorithm::RsaSha1,
        };
        let msg = b"From: a@example.com\r\n\r\nbody\r\n";
        let header = signer
            .sign_with_algorithm(msg, DkimAlgorithm::RsaSha1)
            .unwrap();
        assert!(header.contains("a=rsa-sha1"));
        assert!(header.contains("bh="));
    }

    #[test]
    fn signs_ed25519() {
        // Generate ed25519 key for test
        use ed25519_dalek::SigningKey as EdSigningKey;
        // Use a fixed seed for deterministic test
        let seed = [1u8; 32];
        let sk = EdSigningKey::from_bytes(&seed);
        let key = PrivateKey::Ed25519(sk);
        let signer = DkimSigner {
            domain: "example.com".into(),
            selector: "ed25519".into(),
            headers: vec!["From".into()],
            key,
            algorithm: DkimAlgorithm::Ed25519Sha256,
        };
        let msg = b"From: a@example.com\r\n\r\nbody\r\n";
        let header = signer.sign(msg).unwrap();
        assert!(header.contains("a=ed25519-sha256"));
    }

    #[test]
    fn verifies_rsa_sha256_roundtrip() {
        let key = parse_key(RSA_KEY.as_bytes()).unwrap();
        let signer = DkimSigner {
            domain: "example.com".into(),
            selector: "mail2026".into(),
            headers: vec!["From".into(), "To".into()],
            key,
            algorithm: DkimAlgorithm::RsaSha256,
        };
        let msg = b"From: a@example.com\r\nTo: b@example.com\r\n\r\nhello\r\n";
        let header = signer.sign(msg).unwrap();
        assert!(header.contains("a=rsa-sha256"));
        assert!(header.contains("bh="));
        assert!(header.contains("b="));
        // Check b is base64 and decodes to 256 bytes (2048-bit key)
        let b_start = header.rfind("; b=").unwrap() + 4;
        let b_val: String = header[b_start..]
            .trim_end_matches(';')
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let sig = BASE64.decode(b_val).unwrap();
        assert_eq!(sig.len(), 256);
    }

    #[test]
    fn parses_1024_bit_rsa() {
        use rsa::traits::PublicKeyParts;
        // This is the user’s brambles.org/mail 1024-bit key, embedded as test (same as RSA_KEY but 1024)
        // Generate a 1024-bit key for test
        let mut rng = rand::thread_rng();
        let priv_key = RsaPrivateKey::new(&mut rng, 1024).unwrap();
        let pem = rsa::pkcs8::EncodePrivateKey::to_pkcs8_der(&priv_key).unwrap();
        let pem_str = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
            BASE64.encode(pem.as_bytes())
        );
        let parsed = parse_key(pem_str.as_bytes()).unwrap();
        match &parsed {
            PrivateKey::Rsa(k) => assert_eq!(k.size() * 8, 1024),
            _ => panic!("expected RSA 1024"),
        }
        // Sign with it
        let signer = DkimSigner {
            domain: "example.com".into(),
            selector: "test1024".into(),
            headers: vec!["From".into()],
            key: parsed,
            algorithm: DkimAlgorithm::RsaSha256,
        };
        let msg = b"From: a@example.com\r\n\r\ntest\r\n";
        let h = signer.sign(msg).unwrap();
        assert!(h.contains("b="));
    }

    const REFERENCE_RSA_PKCS1: &str = concat!(
        "-----BEGIN RSA PRIVATE KEY-----\n",
        "MIIEowIBAAKCAQEAv9XYXG3uK95115mB4nJ37nGeNe2CrARm1agrbcnSk5oIaEfM\n",
        "ZLUR/X8gPzoiNHZcfMZEVR6bAytxUhc5EvZIZrjSuEEeny+fFd/cTvcm3cOUUbIa\n",
        "UmSACj0dL2/KwW0LyUaza9z9zor7I5XdIl1M53qVd5GI62XBB76FH+Q0bWPZNkT4\n",
        "NclzTLspD/MTpNCCPhySM4Kdg5CuDczTH4aNzyS0TqgXdtw6A4Sdsp97VXT9fkPW\n",
        "9rso3lrkpsl/9EQ1mR/DWK6PBmRfIuSFuqnLKY6v/z2hXHxF7IoojfZLa2kZr9Ae\n",
        "d4l9WheQOTA19k5r2BmlRw/W9CrgCBo0Sdj+KQIDAQABAoIBAFPChEi/OvnulReB\n",
        "ECQWhOUYuNKlFKQU++2YEvZJ4+bMn5UgnE7wfJ1pj2Pr9xlfALz+OMHNrjMxGbaV\n",
        "KzdrT2uCkYcf78XjnhuH9gKIiXDUv4L4N+P3u6w8yOx4bFgOS9IjS53yDOPM7SC5\n",
        "g6dIg5aigHaHlffqIuFFv4yQMI/+Ai+zBKxS7wRhxK/7nnAuo28fe5MEdp57ho9/\n",
        "AGlDNsdg9zCgjwhokwFE3+AaD+bkUFm4gQ1XjkUFrlmnQn8vDQ0i9toEWhCj+UPY\n",
        "iOKL63MJnr90MXTXWLHoFj99wBp//mYygbF9Lj8fa28/oa8LWp3Jhb7QeMgH46iv\n",
        "3aLHbTECgYEA5M2dAw+nyMw9vYlkMejhwObKYP8Mr/6zcGMLCalYvRJM5iUAM0JI\n",
        "H6sM6pV9/nv167cbKocj3xYPdtE7FPOn4132MLM8Ne1f8nPE64Qrcbj5WBXvLnU8\n",
        "hpWbwe2Z8h7UUMKx6q4F1/TXYkc3ScxYwfjM4mP/pLsAOgVzRSEEgrUCgYEA1qNQ\n",
        "xaQHNWZ1O8WuTnqWd5JSsic6iURAmUcLeFDZY2PWhVoaQ8L/xMQhDYs1FIbLWArW\n",
        "4Qq3Ibu8AbSejAKuaJz7Uf26PX+PYVUwAOO0qamCJ8d/qd6So7qWMDyAY2yXI39Y\n",
        "1nMqRjr7bkEsggAZao7BKqA7ZtmogjOusBT38iUCgYEA06agJ8TDoKvOMRZ26PRU\n",
        "YO0dKLzGL8eclcoI29cbj0rud7aiiMg3j5PbTuUat95TjsjDCIQaWrM9etvxm2AJ\n",
        "Xfn9Uu96MyhyKQWOk46f4YMKpMElkARDCPw8KRhx39dE77AqhLyWCz8iPndCXbH6\n",
        "KPTOEl4OjYOuof2Is9nnIkECgYBh948RdsnXhNlzm8nwhiGRmBbou+EK8D0v+O5y\n",
        "Tyy6IcKzgSnFzgZh8EdJ4EUtBk1f9SqY8wQdgIvSl3daXorusuA/TzkngsaV3YUY\n",
        "ktZOLlF7CKLrjOyPkMWmZKcROmpNyH1q/IvKHHfQnizLdXIkYd4nL5WNX0F7lE1i\n",
        "j1+QhQKBgB2lviBK7rJFwlFYdQUP1NAN2dKxMZk8uJS8JglHrM0+8nRI83HbTdEQ\n",
        "vB0ManEKBkbS4T5n+gRtdEqKSDmWDTXDlrBfcdCHNQLwYtBpOotCqQn/AmfjcPBl\n",
        "byAbwh4+HiZ5JISoRZpiZqy67aJNVoXmdtb/E9mi7ozzytpxMNql\n",
        "-----END RSA PRIVATE KEY-----\n"
    );

    #[test]
    fn matches_mail_auth_reference_vector() {
        // Golden vector from patched mail-auth's own dkim_sign unit test
        // (patches/mail-auth @ bd89ed6): identical key, message, headers and
        // fixed t=311923920 must produce the byte-identical signature.
        let pk = parse_key(REFERENCE_RSA_PKCS1.as_bytes()).unwrap();
        let signer = DkimSigner {
            domain: "stalw.art".into(),
            selector: "default".into(),
            headers: vec!["From".into(), "To".into(), "Subject".into()],
            key: pk,
            algorithm: DkimAlgorithm::RsaSha256,
        };
        let message = concat!(
            "From: hello@stalw.art\r\n",
            "To: dkim@stalw.art\r\n",
            "Subject: Testing  DKIM!\r\n\r\n",
            "Here goes the test\r\n\r\n"
        );
        let header = signer
            .sign_with_time(message.as_bytes(), DkimAlgorithm::RsaSha256, 311_923_920)
            .unwrap();

        // mail-auth's canonical (Display) form differs from the emitted header
        // only in the prefix token and the fold token (SP vs "\r\n\t"); the
        // byte-width accounting is shared. Convert and compare exactly.
        let signed_form = header
            .replacen("DKIM-Signature: ", "dkim-signature:", 1)
            .replace("\r\n\t", " ");
        assert_eq!(
            concat!(
                "dkim-signature:v=1; a=rsa-sha256; s=default; d=stalw.art; ",
                "c=relaxed/relaxed; h=Subject:To:From; t=311923920; ",
                "bh=QoiUNYyUV+1tZ/xUPRcE+gST2zAStvJx1OK078Yl m5s=; ",
                "b=B/p1FPSJ+Jl4A94381+DTZZnNO4c3fVqDnj0M0Vk5JuvnKb5",
                "dKSwaoIHPO8UUJsroqH z+R0/eWyW1Vlz+uMIZc2j7MVPJcGaY",
                "Ni85uCQbPd8VpDKWWab6m21ngXYIpagmzKOKYllyOeK3X qwDz",
                "Bo0T2DdNjGyMUOAWHxrKGU+fbcPHQYxTBCpfOxE/nc/uxxqh+i",
                "2uXrsxz7PdCEN01LZiYVV yOzcv0ER9A7aDReE2XPVHnFL8jxE",
                "2BD53HRv3hGkIDcC6wKOKG/lmID+U8tQk5CP0dLmprgjgTv Se",
                "bu6xNc6SSIgpvwryAAzJEVwmaBqvE8RNk3Vg10lBZEuNsj2Q==;",
            ),
            signed_form
        );
    }

    // The vectors below pin the emitted signature byte-for-byte for message/key
    // shapes the RSA vector above does not cover. Expected bytes were generated
    // with this signer and cross-checked against mail-auth 0.11.2's offline DKIM
    // verifier (independent RFC 6376 canonicalization); mail-auth is NOT a
    // dependency of this crate. ed25519 signing is deterministic (RFC 8032) and
    // every vector fixes t=, so outputs are stable.

    /// RFC 8032 Ed25519 test key (same as mail-auth's ED25519_PRIVATE_KEY);
    /// public key p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=
    const ED25519_SEED_B64: &str = "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=";

    #[test]
    fn matches_ed25519_reference_vector() {
        use ed25519_dalek::SigningKey as EdSigningKey;
        let seed: [u8; 32] = BASE64.decode(ED25519_SEED_B64).unwrap().try_into().unwrap();
        let pk = PrivateKey::Ed25519(EdSigningKey::from_bytes(&seed));
        let signer = DkimSigner {
            domain: "example.com".into(),
            selector: "ed".into(),
            headers: vec!["From".into(), "To".into(), "Subject".into()],
            key: pk,
            algorithm: DkimAlgorithm::Ed25519Sha256,
        };
        let message = concat!(
            "From: hello@stalw.art\r\n",
            "To: dkim@stalw.art\r\n",
            "Subject: Testing  DKIM!\r\n\r\n",
            "Here goes the test\r\n\r\n"
        );
        let header = signer
            .sign_with_time(
                message.as_bytes(),
                DkimAlgorithm::Ed25519Sha256,
                311_923_920,
            )
            .unwrap();
        let signed_form = header
            .replacen("DKIM-Signature: ", "dkim-signature:", 1)
            .replace("\r\n\t", " ");
        assert_eq!(
            concat!(
                "dkim-signature:v=1; a=ed25519-sha256; s=ed; d=example.com; ",
                "c=relaxed/relaxed; h=Subject:To:From; t=311923920; ",
                "bh=QoiUNYyUV+1tZ/xUPRcE+gST2zAStvJx1OK078Yl m5s=; ",
                "b=54jxw+uyT6alxSZqZqTHSfLxxMNwteh+KmAVfABSAI5f4ywBk",
                "HdFllyeH7XKjD6eHBX d72ap20YWJUvWXfxYAw==;",
            ),
            signed_form
        );
    }

    #[test]
    fn matches_reference_vector_duplicate_headers() {
        // Every occurrence of each h= header must be signed in reverse message
        // order (RFC 6376 5.4.2): h=Cc:Subject:To:From:To for this message.
        let key = parse_key(RSA_KEY.as_bytes()).unwrap();
        let signer = DkimSigner {
            domain: "example.com".into(),
            selector: "s2048".into(),
            headers: vec!["From".into(), "To".into(), "Cc".into(), "Subject".into()],
            key,
            algorithm: DkimAlgorithm::RsaSha256,
        };
        let message = concat!(
            "To: one@example.com\r\n",
            "From: bill@example.com\r\n",
            "To: two@example.com\r\n",
            "Subject: Dup\r\n",
            "Cc: c@example.com\r\n\r\n",
            "body\r\n"
        );
        let header = signer
            .sign_with_time(message.as_bytes(), DkimAlgorithm::RsaSha256, 1_756_100_000)
            .unwrap();
        let signed_form = header
            .replacen("DKIM-Signature: ", "dkim-signature:", 1)
            .replace("\r\n\t", " ");
        assert_eq!(
            concat!(
                "dkim-signature:v=1; a=rsa-sha256; s=s2048; d=example.com; ",
                "c=relaxed/relaxed; h=Cc:Subject:To:From:To; t=1756100000; ",
                "bh=Ck5SoRNWUpSR4X0COv7R5ub2pUTtl6xz4 dTFz++ji4M=; ",
                "b=YqQnMzHJXs5Dr65uGRiLHOu0EPTIxYucAKFtD4EQ3aD6m7x/7HyeW6YWPOIr ",
                "xdYFKIz8bms9CsRd2jWreBaiG3I8R6i24TScao3l0yHquyNlfBZMfmelttejJ6cjWQEAyhH/ZWi ",
                "QJyVOSWNIe1Ahp5ahCEbG0NwlfhFma7Clyb1esQldiUt3Icxx8zxYp9gYqjzBjwC3Lnxse1jDzE ",
                "2mEV4e9U0JYEERj4IWF2pZ2OVQr2XOKrpvRLnBlsxK4fP1eYj9r9QnZjKrXf3xCrKUVZlN+dK/S ",
                "m/w9+sC2SkNyWmsI7BoFt7xr3jH3pBcDFiCyf966eNslK9l87HMtUnLcA==;",
            ),
            signed_form
        );
    }

    #[test]
    fn matches_reference_vector_whitespace_body() {
        // Relaxed body canonicalization: strip trailing WSP per line, compress
        // inner WSP runs to single SP, drop trailing empty lines.
        let key = parse_key(RSA_KEY.as_bytes()).unwrap();
        let signer = DkimSigner {
            domain: "example.com".into(),
            selector: "s2048".into(),
            headers: vec!["From".into(), "To".into(), "Subject".into()],
            key,
            algorithm: DkimAlgorithm::RsaSha256,
        };
        let message = concat!(
            "From: a@example.com\r\n",
            "To: b@example.com\r\n",
            "Subject: WSP Test\r\n\r\n",
            "line   with\ttabs   \r\n",
            "next  line  \r\n\r\n\r\n"
        );
        let header = signer
            .sign_with_time(message.as_bytes(), DkimAlgorithm::RsaSha256, 1_756_100_001)
            .unwrap();
        let signed_form = header
            .replacen("DKIM-Signature: ", "dkim-signature:", 1)
            .replace("\r\n\t", " ");
        assert_eq!(
            concat!(
                "dkim-signature:v=1; a=rsa-sha256; s=s2048; d=example.com; ",
                "c=relaxed/relaxed; h=Subject:To:From; t=1756100001; ",
                "bh=aWEYJY1JuVJX863P/e9X5RqSVFfqgnaavHQ0stQ D/0s=; ",
                "b=b1x5akK8y1mEv07hsuhPDmvNF9i9LZmawjZCiaH4Qba5+LmKt0IUq1XXHTqeXT81qd ",
                "t9O+KcGAoGv8Bsfg61B6nruYSVJAkXdijDIBgITcpsiIQTbcRz39SVDOHW8HvFMSgq1D1m84SmP ",
                "LynebIt/81ohiXHPyCo2ITfcSaNS5R81tmsnKEAudanW9+LYMQc59hjgBmLlrtOYMel/R0G3iF+ ",
                "oQcSxs+oyKKrMIyphH4AQjL9Xl5mQRQbjsvqdu4+kbB6hmTv0j4W8/+QX7de1z4fJ4ITC59fysk ",
                "lW14Qp5/99fVC8xJwZT1Zi3KldjkRtu6koUV06FzUuV6RyptxkA==;",
            ),
            signed_form
        );
    }

    #[test]
    fn matches_reference_vector_empty_body() {
        // Empty body hashes to sha256("") under relaxed canonicalization
        // (bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=).
        let key = parse_key(RSA_KEY.as_bytes()).unwrap();
        let signer = DkimSigner {
            domain: "example.com".into(),
            selector: "s2048".into(),
            headers: vec!["From".into(), "To".into(), "Subject".into()],
            key,
            algorithm: DkimAlgorithm::RsaSha256,
        };
        let message = concat!(
            "From: e@example.com\r\n",
            "To: f@example.com\r\n",
            "Subject: Empty\r\n\r\n",
            "\r\n"
        );
        let header = signer
            .sign_with_time(message.as_bytes(), DkimAlgorithm::RsaSha256, 1_756_100_002)
            .unwrap();
        let signed_form = header
            .replacen("DKIM-Signature: ", "dkim-signature:", 1)
            .replace("\r\n\t", " ");
        assert_eq!(
            concat!(
                "dkim-signature:v=1; a=rsa-sha256; s=s2048; d=example.com; ",
                "c=relaxed/relaxed; h=Subject:To:From; t=1756100002; ",
                "bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3h SuFU=; ",
                "b=XZWu0hbg2urQuqgrpBpFPBUR8JnmtzVbjg39DCbIfiHNbVzNqVRoEwZ8/xsVoEwWl9 ",
                "JCfgYNm6AFsbtOcF+Tv5msnXXOGPO9gluujmdHi38wStcc4iySw/+JxSf3b+tk56xIIvr8vZkN3 ",
                "Mnayqle3RbBKr4OdJajJtKNGnp2pybMiZLsamgmFKMlGoYqk60vbjcIdUP2dv4RyQ/06PNBGKC9 ",
                "1Ee4juF0c7Sk07jbS7psuhbalU2uP+H208WDrHsloZ6Y8E1dcUAus9kwtTSzX9pag8IumfZBUiq ",
                "+iX9hOFIBOE6xWzZEwkKJadeFSbPLZg0OePOnSGNI4CyxmyUmBw==;",
            ),
            signed_form
        );
    }
}
