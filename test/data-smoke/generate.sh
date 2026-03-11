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

# --- TLS certificate + key ---
mkdir -p "$DIR/tls"
if [ ! -f "$DIR/tls/server.key" ] || [ ! -f "$DIR/tls/server.crt" ]; then
  openssl ecparam -genkey -name prime256v1 -noout -out "$DIR/tls/server.key" 2>/dev/null
  openssl req -new -x509 -key "$DIR/tls/server.key" \
    -out "$DIR/tls/server.crt" \
    -days 365 -subj "/CN=containd" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
  echo "Generated tls/server.{key,crt}"
else
  echo "tls/server.{key,crt} already exist, skipping"
fi

# --- Directories the app expects ---
mkdir -p "$DIR/ssh/authorized_keys.d"
mkdir -p "$DIR/services"

echo "Done.  Databases will be created automatically on first run."
