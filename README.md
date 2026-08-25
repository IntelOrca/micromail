# micromail

Lightweight outbound SMTP relay + CLI mail sender (direct MX or relay). Rust 2021, `axum` + `mail-send` + `hickory-resolver`.

## Quickstart (non-root, direct MX)

```bash
cargo build
# dev spool/api/smtp on localhost — see dev-config/config.toml
cargo run -- -c ./dev-config -v serve
# in another shell:
cargo run -- -c ./dev-config -v send --from you@example.com --to test@srv.mailtested.com --subject "hi" --text "hello"
# REST:
curl -s http://127.0.0.1:18080/health
curl -s -H "Authorization: Bearer dev-token-123" -H "Content-Type: application/json" \
  -d '{"from":"you@example.com","to":["test@example.com"],"subject":"hi","text":"hello"}' \
  http://127.0.0.1:18080/send
```

Production: copy `config.toml.example` to `/etc/micromail/config.toml` (`-c` defaults to `/etc/micromail` `src/config.rs:5`). TLS certs auto-detected at `<config>/tls/cert.pem`+`key.pem` `src/config.rs:184`.

## Config

`config.toml` TOML, all optional (defaults if absent `src/config.rs:150`). Keys: `hostname`, `log`, `max_message_size` (25M), `max_recipients` (100), `[smtp]` (`enabled`, `listen=:587`, `tls_listen=:465`, `[[smtp.users]]`), `[api]` (`enabled`, `listen=:8080`, `tokens`), `[dkim]` (`enabled`), `[delivery]` (`relay`, `relay_tls=auto/starttls/tls/plain`, `timeout_secs=30`), `[retry]` (`max_attempts=5`, `initial_delay_secs=60`, `backoff_factor=2`). See `config.toml.example`.

## DKIM
Per-domain keys under `<config>/dkim/<domain>/` `src/dkim.rs:35`:
```
dev-config/dkim/example.com/
  key.pem          # dkim.pem|private.pem|key.pem (RSA 2048+ PKCS1/PKCS8 or Ed25519 PKCS8) src/dkim.rs:108
  selector         # optional, defaults to dkim_selector_default
```
Validate before use (`parse_key` `src/dkim.rs:148`). To generate:
```bash
mkdir -p dev-config/dkim/example.com
openssl genrsa -out dev-config/dkim/example.com/key.pem 2048
echo -n "default" > dev-config/dkim/example.com/selector
# publish TXT:  default._domainkey.example.com  ->  v=DKIM1; k=rsa; p=<base64 of pubkey>
```
Send a test mail and inspect `DKIM-Signature` / `Authentication-Results: dkim=pass` on the receiver (e.g. `srv.mailtested.com` checker).

## Direct MX
When `delivery.relay` is unset, `Delivery::deliver_direct` `src/send.rs:162` groups by recipient domain, resolves MX `src/send.rs:312` (MX preference-sorted, A fallback), tries each host `:25` `src/send.rs:187` with `auto` TLS (implicit 465 else STARTTLS→plain). Needs egress `:25` open — many clouds block it. Test: `dig MX example.com; nc -vz <mx> 25`. Requires `SPF`/`PTR`/`hostname` DNS for deliverability.

Relay mode: set `delivery.relay="smtp.provider.com:587"` + creds.

## Daemon
`main.rs:40` spawns spool worker `src/queue.rs:214` (mpsc wake + 10s tick), SMTP `src/smtp.rs:56` (PLAIN/LOGIN, STARTTLS, DATA `src/smtp.rs:555`), API `src/api.rs:60`. Spool `spool/<uuid>/{meta.toml,message.eml}` atomic `src/queue.rs:76`, backoff `src/queue.rs:177`, `failed/` after `max_attempts`. Spool creation is warn-only for non-root `src/queue.rs:46`. `-v/--verbose` `src/cli.rs:16` enables `debug` (quiet hickory/rustls unless `RUST_LOG` set `src/main.rs:161`).

## Tests
```bash
cargo test       # 34 unit tests
cargo clippy --all-targets
```

## Files
`src/send.rs` outbound, `src/smtp.rs` submission, `src/api.rs` REST, `src/queue.rs` spool, `src/dkim.rs` signing, `src/message.rs` build, `src/config.rs` load, `src/cli.rs` args, `src/main.rs` entry.
