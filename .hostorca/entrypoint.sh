#!/bin/sh
# Renders micromail's configuration from the environment, then runs the daemon.
#
# Every value that differs between instances — the hostname, the SMTP users, the
# API tokens — arrives as an environment variable, so nothing here has to be
# edited per instance. The rendered config.toml stays inside the container; the
# data volume holds only the spool and the DKIM keys.
set -eu

CONFIG_DIR=/etc/micromail
DATA_DIR=/data

: "${MAIL_HOSTNAME:?MAIL_HOSTNAME is required}"
: "${SMTP_USERNAME:?SMTP_USERNAME is required}"
: "${SMTP_PASSWORD:?SMTP_PASSWORD is required}"
: "${API_TOKEN:?API_TOKEN is required}"

mkdir -p "$CONFIG_DIR" "$DATA_DIR/spool" "$DATA_DIR/dkim"
ln -sfn "$DATA_DIR/spool" "$CONFIG_DIR/spool"
ln -sfn "$DATA_DIR/dkim" "$CONFIG_DIR/dkim"

cat > "$CONFIG_DIR/config.toml" <<EOF
# Rendered from the environment at container start; change hostorca.yml instead.
hostname = "${MAIL_HOSTNAME}"
log = "info"

[smtp]
enabled = true
listen = "0.0.0.0:587"
tls_listen = "0.0.0.0:465"
# AUTH is accepted on a plaintext connection: this replaces a relay whose
# clients authenticate on port 25, which has no TLS.
allow_auth_insecure = ${ALLOW_AUTH_INSECURE:-false}

[[smtp.users]]
username = "${SMTP_USERNAME}"
password = "literal:${SMTP_PASSWORD}"

[api]
enabled = true
listen = "0.0.0.0:8080"

[[api.tokens]]
name = "local"
token = "literal:${API_TOKEN}"
EOF

exec micromail -c "$CONFIG_DIR" "$@"
