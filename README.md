<div align="center">

# micromail

**A tiny, self-hostable outbound email relay.**

[SMTP submission](#1-smtp) · [REST API](#3-rest-api) · [CLI](#1-cli) · [DKIM signing](#dkim-setup)

[![CI](https://github.com/IntelOrca/micromail/actions/workflows/ci.yml/badge.svg)](https://github.com/IntelOrca/micromail/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/IntelOrca/micromail)](https://github.com/IntelOrca/micromail/releases)
![Rust](https://img.shields.io/badge/rust-stable-orange?logo=rust)

</div>

---

micromail is a single small executable (<16 MiB, ~11 MB release build) that sends email for you.
It accepts mail over SMTP, HTTP, or the command line, signs it with DKIM, and delivers it
straight to the recipient's MX servers — or through your existing provider if you prefer.
No daemons-of-daemons, no databases: one binary, one TOML file.

## Features

- **SMTP submission server** — port 587 (STARTTLS) and 465 (implicit TLS), AUTH PLAIN/LOGIN
- **REST API** — `POST /send` with bearer-token auth, `GET /health`
- **CLI sender** — one-shot synchronous sends from scripts and cron jobs
- **DKIM signing** — RSA (2048+) and Ed25519 keys, multiple selectors for rotation
- **Direct MX delivery** — resolves recipient MX records itself; or relay through any provider
- **Persistent spool** — atomic writes, retry with exponential backoff, dead-letter folder
- **Layered configuration** — `/etc/micromail` overlaid by `~/.config/micromail`
- **Small & fast** — a single <16 MiB binary built in Rust; no runtime dependencies

## Quickstart

Build and install:

```bash
git clone https://github.com/IntelOrca/micromail
cd micromail
cargo build --release          # produces ./target/release/micromail (~11 MB)
```

Create a minimal config:

```bash
mkdir -p ~/.config/micromail
cp config.toml.example ~/.config/micromail/config.toml
$EDITOR ~/.config/micromail/config.toml   # set an smtp user + api token
```

```toml
hostname = "mail.example.com"

[[smtp.users]]
username = "app"
password = "literal:change-me"

[api]

[[api.tokens]]
name = "ci-server"
token = "literal:change-me-token"
```

Start the daemon:

```bash
./target/release/micromail serve
curl http://127.0.0.1:8080/health   # → {"status":"ok"}
```

## Send an email

Three ways, pick whichever suits the caller.

### 1. CLI

One-shot send, no daemon required:

```bash
micromail send \
  --from you@example.com \
  --to dest@example.net \
  --subject "Hello" \
  --text "Sent straight from the command line."
```

Also available: `--cc`, `--bcc`, `--html`, `--text-file`, `--html-file` (repeatable recipients).

### 2. SMTP

Point any standard client or library at port 587:

```bash
swaks --server 127.0.0.1:587 \
      --auth PLAIN --auth-user app --auth-password change-me \
      --from you@example.com --to dest@example.net \
      --header "Subject: Hello" --body "Sent over SMTP."
```

### 3. REST API

```bash
curl -X POST http://127.0.0.1:8080/send \
  -H "Authorization: Bearer change-me-token" \
  -H "Content-Type: application/json" \
  -d '{
    "from":    "you@example.com",
    "to":      ["dest@example.net"],
    "subject": "Hello",
    "text":    "Sent over HTTP."
  }'
```

Body fields: `from` *(required)*, `to`, `cc`, `bcc` *(arrays)*, `subject`, `text`, `html`.

## Configuration

Copy `config.toml.example` to `~/.config/micromail/config.toml` (or `/etc/micromail/config.toml`)
and edit it. Every key is optional — absent values fall back to the defaults below.
The user directory is merged over the system directory (user wins), and `-c <dir>`
points at exactly one directory instead.

<details>
<summary><strong>All options</strong></summary>

| Key | Default | Description |
|---|---|---|
| `hostname` | — | Name presented in EHLO and message headers |
| `log` | `"info"` | `trace`, `debug`, `info`, `warn`, `error` |
| `max_message_size` | `26214400` | Max accepted message size in bytes (25 MiB) |
| `max_recipients` | `100` | Max recipients per envelope |
| `dkim_selector_default` | `"default"` | Selector used when signing |

**`[smtp]`**

| Key | Default | Description |
|---|---|---|
| `enabled` | `true` | |
| `listen` | `"0.0.0.0:587"` | Plain listener with STARTTLS |
| `tls_listen` | `"0.0.0.0:465"` | Implicit TLS; active only when cert+key exist |
| `cert` / `key` | auto | Defaults to `<config>/tls/cert.pem` and `<config>/tls/key.pem` |

Per-user credentials via `[[smtp.users]]`: `username`, `password`,
and optional `allow_auth_insecure` (`false` by default — AUTH requires TLS).
Usernames are matched ASCII case-insensitively; passwords exactly.

**`[api]`**

| Key | Default | Description |
|---|---|---|
| `enabled` | `true` | |
| `listen` | `"0.0.0.0:8080"` | |
| `[[api.tokens]]` | `[]` | Bearer tokens accepted by `POST /send`; each has a `name` (identifier) and `token` |

**`[delivery]`**

| Key | Default | Description |
|---|---|---|
| `relay` | unset | Unset = direct MX delivery; e.g. `"smtp.provider.com:587"` |
| `relay_username` / `relay_password` | — | Relay credentials (`relay_password` accepts `literal:` only) |
| `relay_tls` | `"auto"` | `auto`, `starttls`, `tls`, `plain` |
| `timeout_secs` | `300` | Per-delivery timeout |

**`[retry]`**

| Key | Default | Description |
|---|---|---|
| `max_attempts` | `5` | Messages then move to the spool's `failed/` folder |
| `initial_delay_secs` | `60` | First retry delay |
| `backoff_factor` | `2` | Delay multiplier per attempt |

</details>

<details>
<summary><strong>DKIM setup</strong></summary>

Keys live per-domain under the config dir; the file name is the selector and the contents are
a PEM private key (RSA 2048+ PKCS1/PKCS8, or Ed25519 PKCS8):

```
~/.config/micromail/dkim/example.com/
├── default       # PEM private key, selector = default
└── mail2026      # second selector, e.g. for rotation
```

Generate an RSA key and publish its public half in DNS:

```bash
mkdir -p ~/.config/micromail/dkim/example.com
openssl genrsa -out ~/.config/micromail/dkim/example.com/default 2048
chmod 600 ~/.config/micromail/dkim/example.com/default

openssl rsa -in ~/.config/micromail/dkim/example.com/default -pubout \
  | grep -v -- ----- | tr -d '\n'
```

Publish as a TXT record:

```
default._domainkey.example.com  IN TXT  "v=DKIM1; k=rsa; p=<base64 public key>"
```

Notes:

- Private keys must be readable only by the owner (`0600` or `0400`) — group/other access is rejected.
- Signing uses `dkim_selector_default`; if that file is missing but exactly one key exists,
  it is used instead. Multiple selectors make rotation a drop-in affair.
- Verify end-to-end by sending a test mail and checking the `DKIM-Signature` header /
  `Authentication-Results: dkim=pass`.

</details>

<details>
<summary><strong>Credential storage prefixes</strong></summary>

Passwords and API tokens must carry a prefix declaring how they are stored:

| Prefix | Meaning |
|---|---|
| `literal:<value>` | Plaintext secret, compared in constant time |
| `argon2:<PHC string>` | Argon2 hash; candidates are verified with Argon2id using the parameters embedded in the hash |

```toml
[[smtp.users]]
username = "app"
password = "argon2:$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>"

[[api.tokens]]
name = "ci-server"
token = "literal:change-me-token"
```

Generate an Argon2id PHC string with any standard tool, e.g.
`echo -n "change-me" | argon2 "$(head -c 16 /dev/urandom | base64)" -id -t 2 -m 14 -p 1 -e`.

Unprefixed values are rejected at startup. `delivery.relay_password` accepts
`literal:` only — the plaintext is required to authenticate against the remote relay.

Note that each `argon2:` verification costs ~19 MiB of memory and tens of
milliseconds of CPU (SMTP AUTH attempts and API requests are verified off the
async runtime, but the cost per attempt still applies). Prefer `literal:`
secrets for high-throughput endpoints.

</details>

### Delivery modes

- **Direct MX (default)** — micromail groups recipients by domain, resolves each domain's MX
  records, and delivers on port 25 with opportunistic TLS. Requires outbound port 25
  (blocked on many clouds), plus proper SPF/PTR/`hostname` DNS for good deliverability.
- **Relay** — set `[delivery] relay = "smtp.provider.com:587"` (+ credentials) and everything
  is handed to your provider instead.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## License

micromail is licensed under the [MIT license](LICENSE).
