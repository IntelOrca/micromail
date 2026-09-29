## Unreleased

- Fix: DKIM TXT record for RSA keys now publishes `p=` as a DER SubjectPublicKeyInfo (RFC 6376 section 3.6.1) instead of a bare PKCS#1 RSAPublicKey, which strict verifiers reject as an unusable key. Keys published by earlier versions can be converted by prefixing `MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A` to a 2048-bit `p=` value; the private key is unchanged.

## 0.2.0 (2026-09-20)

- Feature: DKIM key generation - `micromail dkim generate <domain>` (RSA 2048 default / Ed25519, 0600 perms, selector validation, syncs `dkim_selector_default`, prints TXT record).
- Feature: DNS helpers - `micromail dns dkim <domain>` and `micromail dns spf <domain>` (`--ip`, `--include`, `--auto-ip`, `--hostname`, `--format human|bind`, BIND 255-byte chunking).
- Feature: Static musl binary - `micromail-*-x86_64-musl` CI artifact and release asset for Alpine.
- Fix: Install rustls `ring` crypto provider in delivery resolver (fixes `queue::tests` / production MX-delivery panic).
- Fix: Gate unix-only `PermissionsExt` assertion in DKIM test for Windows CI.

## 0.1.0 (2026-08-26)

- Feature: Lightweight outbound SMTP relay - a single <16 MiB binary, one TOML file, no daemons-of-daemons or databases.
- Feature: SMTP submission server - port 587 (STARTTLS) and 465 (implicit TLS), AUTH PLAIN/LOGIN, ASCII case-insensitive usernames.
- Feature: REST API - `POST /send` with bearer-token auth, `GET /health`.
- Feature: CLI sender - one-shot synchronous sends (`send` subcommand) with `--from`, `--to`, `--cc`, `--bcc`, `--subject`, `--text`, `--html` and file variants.
- Feature: DKIM signing - RSA 2048+ and Ed25519 keys, per-domain `<config>/dkim/<domain>/<selector>`, multiple selectors for rotation.
- Feature: Direct MX delivery - per-domain MX resolution, opportunistic TLS on port 25; or relay via `[delivery] relay`.
- Feature: CLI config management - `config get/set`, `user add/passwd/remove/list`, `token add/rotate/remove/list`, Argon2id or `literal:` storage.
- Feature: Persistent spool - atomic writes to `<config>/spool`, exponential backoff retry, dead-letter `spool/failed`.
- Feature: Layered configuration - `/etc/micromail` overlaid by `~/.config/micromail`, `-c <dir>` override, TLS cert auto-discovery.
