#!/usr/bin/env bash
# generate.sh -- create fresh smoke-test fixtures.
# The containd binary auto-generates all of these on startup, so running
# this script is optional.  It is provided for convenience when you want
# the files to exist before launching the container.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"

# --- SSH host key ---
mkdir -p "$DIR/ssh"
if [ ! -f "$DIR/ssh/host_key" ]; then
  ssh-keygen -t ed25519 -f "$DIR/ssh/host_key" -N "" -q
  rm -f "$DIR/ssh/host_key.pub"   # not needed by the server
  echo "Generated ssh/host_key"
else
  echo "ssh/host_key already exists, skipping"
fi

# --- Management TLS bundle (offline only; stop the smoke stack first) ---
# Never rewrite the legacy server.crt/server.key files retained for downgrade.
mkdir -p "$DIR/tls"
if [ ! -f "$DIR/tls/server.pem" ]; then
  (
    umask 077
    key="$(openssl ecparam -genkey -name prime256v1 -noout 2>/dev/null)"
    cert="$(printf '%s\n' "$key" | openssl req -new -x509 -key /dev/stdin \
      -days 365 -subj "/CN=containd" \
      -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null)"
    bundle="$(mktemp "$DIR/tls/.server.XXXXXX")"
    printf '%s\n%s\n' "$cert" "$key" > "$bundle"
    mv "$bundle" "$DIR/tls/server.pem"
  )
  echo "Generated tls/server.pem"
else
  echo "tls/server.pem already exists, skipping"
fi

# --- Directories the app expects ---
mkdir -p "$DIR/ssh/authorized_keys.d"
mkdir -p "$DIR/services"

echo "Done.  Databases will be created automatically on first run."
