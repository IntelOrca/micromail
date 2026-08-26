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
