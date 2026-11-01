# Remote-access kernel smoke

Run from the repository root:

```sh
bash scripts/smoke-remote-access.sh
```

Requires Docker Desktop (Linux WireGuard and `/dev/net/tun`), Compose, curl,
jq and Bash 3 or newer. Builds the current checkout's appliance and an Alpine
client image locally. No host networking or VPN ports are published. Management
uses an ephemeral loopback HTTPS port; curl accepts the generated test certificate.

The fixed `rasmoke` project must not already exist. All addresses, including
tunnels, use `10.250.0.0/16`; ensure it is free. The script refuses to touch an
existing project and always removes its own containers, networks and data volume.
Image tags include the checkout revision. Local images are retained.

Set `RA_LOG_DIR` to a new evidence directory (default: a timestamped directory
under `build/remote-access/`). Logs are private because profiles contain client
keys. Temporary profiles and keys are confined to a private temporary directory.
On failure the harness stops immediately and preserves diagnostics, not the
running stack. Every check emits a named PASS/FAIL; exit 1 means a failed check,
exit 2 a prerequisite/harness failure.

Configuration reads retain their snapshot revision; saves and commits chain
the acknowledged revisions without retrying conflicts. Credential issuance
and revocation use the separate service authority, not the candidate revision.

The quarantine fixture deliberately edits only the stopped, disposable running
SQLite snapshot. No public API can introduce a new service fault: candidate and
import paths validate new content. This models a pre-upgrade configuration, as
the config store tests do, rather than weakening public validation.
