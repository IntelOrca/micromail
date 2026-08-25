# micromail

Lightweight outbound SMTP relay + CLI mail sender (direct MX or relay). Rust 2021, `axum` + `mail-send` + `hickory-resolver`.

## Quickstart (direct MX, user config)

```bash
cargo build
# default config dir is ~/.config/micromail (merged over /etc/micromail) — see src/config.rs:5 + default_config_dir
cargo run -- -v serve              # uses ~/.config/micromail
cargo run -- -c /etc/micromail -v serve  # system dir
# in another shell:
cargo run -- -v send --from you@example.com --to test@srv.mailtested.com --subject "hi" --text "hello"
# REST:
curl -s http://127.0.0.1:8080/health   # or 18080 if using dev example
curl -s -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"from":"you@example.com","to":["test@example.com"],"subject":"hi","text":"hello"}' \
  http://127.0.0.1:8080/send
```

Config merging: `~/.config/micromail` overlays `/etc/micromail` (user wins, dkim merged). Explicit `-c ./dev-config` uses that dir only (tests).

Production: copy `config.toml.example` to `~/.config/micromail/config.toml` or `/etc/micromail/config.toml` (`-c` overrides). TLS certs auto-detected at `<config>/tls/cert.pem`+`key.pem` `src/config.rs:184`.

## Config

`config.toml` TOML, all optional (defaults if absent `src/config.rs:150`). Keys: `hostname`, `log`, `max_message_size` (25M), `max_recipients` (100), `[smtp]` (`enabled`, `listen=:587`, `tls_listen=:465`, `[[smtp.users]]`), `[api]` (`enabled`, `listen=:8080`, `tokens`), `[dkim]` (`enabled`), `[delivery]` (`relay`, `relay_tls=auto/starttls/tls/plain`, `timeout_secs=300`), `[retry]` (`max_attempts=5`, `initial_delay_secs=60`, `backoff_factor=2`). See `config.toml.example`.

## DKIM
Per-selector files under `<config>/dkim/<domain>/<selector>` `src/dkim.rs:35` — filename is selector, contents PEM private key (RSA 2048+ PKCS1/PKCS8 or Ed25519 PKCS8). Strict: no legacy `key.pem+selector` file, private key must be `0600`/`0400` (`0o077` group/other rejected like SSH `src/dkim.rs:108`).
```
~/.config/micromail/dkim/example.com/
  default          # PEM private key, selector = default
  mail2026         # optional second selector for rotation
```
Validate via `parse_key` `src/dkim.rs:148`. To generate:
```bash
mkdir -p ~/.config/micromail/dkim/example.com
openssl genrsa -out ~/.config/micromail/dkim/example.com/default 2048
chmod 600 ~/.config/micromail/dkim/example.com/default
# publish TXT:  default._domainkey.example.com  ->  v=DKIM1; k=rsa; p=<base64 of pubkey>
# extract pub: openssl rsa -in ~/.config/micromail/dkim/example.com/default -pubout | grep -v -- ----- | tr -d '\n'
```
`dkim_selector_default="default"` `src/config.rs:19` selects which file to sign with; if exactly one file exists it is used even when default mismatches, otherwise error on ambiguous multiple.

Send a test mail and inspect `DKIM-Signature` / `Authentication-Results: dkim=pass`.

## Direct MX
When `delivery.relay` is unset, `Delivery::deliver_direct` `src/send.rs:162` groups by recipient domain, resolves MX `src/send.rs:312` (MX preference-sorted, A fallback), tries each host `:25` `src/send.rs:187` with `auto` TLS. Needs egress `:25` open — many clouds block it. Test: `dig MX example.com; nc -vz <mx> 25`. Requires `SPF`/`PTR`/`hostname` DNS.

Relay mode: set `delivery.relay="smtp.provider.com:587"` + creds.

## Daemon
`main.rs:40` spawns spool worker `src/queue.rs:214` (mpsc wake + 10s tick), SMTP `src/smtp.rs:56` (PLAIN/LOGIN, STARTTLS, DATA `src/smtp.rs:555`), API `src/api.rs:60`. Spool `spool/<uuid>/{meta.toml,message.eml}` atomic `src/queue.rs:76`, backoff `src/queue.rs:177`, `failed/` after `max_attempts`. Spool creation is warn-only for non-root `src/queue.rs:46`. `-v/--verbose` `src/cli.rs:16` enables `debug` (quiet hickory/rustls unless `RUST_LOG` set `src/main.rs:161`).

## Tests
```bash
cargo test       # 40 unit tests (temp dirs, no network)
cargo clippy --all-targets
```

## Files
`src/send.rs` outbound, `src/smtp.rs` submission, `src/api.rs` REST, `src/queue.rs` spool, `src/dkim.rs` signing (strict permissions), `src/message.rs` build, `src/config.rs` merged load, `src/cli.rs` args, `src/main.rs` entry.
