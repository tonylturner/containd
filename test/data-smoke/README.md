# Smoke-Test Data Directory

This directory is mounted as `/data` inside the smoke-test container
(see `deploy/docker-compose.smoke.yml`).

All fixture files (keys, certificates, databases) are **generated at
runtime** by the containd binary itself:

- `ssh/host_key` -- auto-generated Ed25519 key on first SSH listen
- `tls/server.crt`, `tls/server.key` -- auto-generated ECDSA P-256
  self-signed certificate on first HTTPS listen
- `*.db` -- SQLite databases created with `CREATE TABLE IF NOT EXISTS`

If you want to pre-populate the directory before starting the container,
run the helper script:

```sh
./generate.sh
```

**Do not commit private keys or database files to the repository.**
