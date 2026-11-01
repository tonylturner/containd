# Docker Compose

This repo ships `deploy/docker-compose.yml` as the supported starter topology for the combined appliance (`containd all`). It is `.env`-driven, image-based, and gives containd an eight-role Docker lab layout (`wan`, `dmz`, `lan1` through `lan6`).

Docker Compose owns the available networks, interface attachments, and Docker-level IP addresses. containd owns the security policy inside that topology: zone binding, routing intent, firewalling, DPI, services, and monitoring.

containd is designed to segment container-to-container traffic inside Docker-based labs. Linux Docker hosts are supported, and Docker Desktop is also a valid lab target because the traffic being filtered lives inside Docker's Linux VM. On Windows, use Docker Desktop with the WSL2 backend. containd is not a native host firewall for macOS or Windows networking.

## Quickstart

```bash
curl -fsSLO https://raw.githubusercontent.com/tonylturner/containd/main/scripts/quickstart.sh
sh quickstart.sh
```

`quickstart.sh` prepares the starter compose and `.env` in the current directory, generates `CONTAIND_JWT_SECRET` when blank, and starts the stack. It reuses existing files unless `--force` is set; explicit option overrides still update `.env`. On a fresh setup, it can adjust the default subnets to avoid existing Docker networks when Python 3 is available.

If you want a customized starter directory before first boot, use the advanced bootstrap script instead:

```bash
curl -fsSLO https://raw.githubusercontent.com/tonylturner/containd/main/scripts/bootstrap-starter.sh
sh bootstrap-starter.sh --dir containd-lab --no-start
cd containd-lab
# edit .env if needed
docker compose up -d
```

If you cloned the repo locally, you can still use the same starter compose directly:

```bash
# Create .env with a generated signing key (do not overwrite an existing .env).
(set -C; sed "s/^CONTAIND_JWT_SECRET=.*/CONTAIND_JWT_SECRET=$(openssl rand -hex 32)/" .env.example > .env)
# Optionally edit .env for ports or lab subnets before starting.
docker compose --env-file .env -f deploy/docker-compose.yml up -d
bash scripts/containd-connect
```

Tip: `bash scripts/containd up` wraps `docker compose --env-file .env -f deploy/docker-compose.yml up -d` and prints connection info automatically when a repo-root `.env` exists.

`scripts/containd-connect` also passes the repository-root `.env` when present.
Compose interpolation errors are reported directly and stop the helper, rather
than being reported as a stopped service.

The starter compose enables nftables enforcement by default so a fresh lab behaves like a firewall once you bind zones and commit policy. It also runs the appliance as `root` inside the container because nftables, routing, and TUN operations need that privilege across Linux, Docker Desktop, and WSL-backed lab environments. Set `CONTAIND_ENFORCE_ENABLED=0` only when you intentionally want an observe-only/demo mode.

## Configuration via `.env`

For a bootstrapped starter, run Compose in the directory containing its `.env`
and `docker-compose.yml`. For a repository checkout, use the explicit
`--env-file .env -f deploy/docker-compose.yml` arguments shown above.

- `.env` is ignored by git (do not commit secrets).
- `.env.example` is the committed template.
- Config-seeding variables apply to a fresh appliance. Once the config DB exists, edit saved policy and services through the UI/API and commit. JWT secrets, listener overrides, reservation authority, and Docker port mappings remain deployment/runtime settings; they are not one-time seeds.
- If you run `deploy/docker-compose.yml` from the cloned repo root, pass `--env-file .env` so Compose uses the repo-root file instead of looking for `deploy/.env`.

### Common variables

- `CONTAIND_IMAGE`: image tag to run in the starter compose. Defaults to `ghcr.io/tonylturner/containd:latest`.
- `CONTAIND_JWT_SECRET`: required non-empty JWT signing key for UI/API auth. Generate it with `openssl rand -hex 32` and keep it private.
- `CONTAIND_LAB_MODE`: leave at `0` for normal deployments. Set to `1` only for disposable lab/dev auth behavior.
- `CONTAIND_ENFORCE_ENABLED`: starter compose default is `1` so nftables enforcement is active once policy is committed. Set `0` only for observe-only runs.
- `CONTAIND_COOKIE_SECURE`: set to `1` when running behind HTTPS (or a TLS-terminating proxy) to force the `Secure` cookie flag.
- `CONTAIND_TRUSTED_PROXIES`: comma-separated list of proxy IPs/CIDRs you trust for client IP resolution (e.g. `127.0.0.1,::1,10.0.0.0/8`).
- `CONTAIND_ALLOWED_ORIGINS`: optional comma-separated browser origins that may embed or call the appliance cross-origin. Starter and dev Compose pass it through to management. Leave empty unless you intentionally integrate containd into another UI or portal.

The default `:latest` tag moves only to signed, SBOM-attached stable releases whose commits have reached main; prereleases never move it. Pin `CONTAIND_IMAGE` to a version tag or digest for a fixed lab release. See [Update Policy](update-policy.md#when-latest-moves).

### Management HTTPS mounts and rotation

The default writable `/data` volume holds the atomically replaced management
identity `/data/tls/server.pem`. A valid legacy `server.crt`/`server.key` pair
at the default paths is imported automatically without changing the originals.
For operator-owned credentials, set `CONTAIND_TLS_CERT_FILE` and
`CONTAIND_TLS_KEY_FILE` to the **same bundle path** and mount its containing
directory read-only. Rotate by atomically replacing that bundle on the host;
a single-file bind mount can pin the old inode. External paths are never
modified by containd, and certificate uploads return 409 in external mode.
See [Management HTTPS identity](config-format.md#management-https-identity)
for migration, split-file limitations, status and reset behavior.

### Management ↔ Engine connectivity

The management plane talks to the engine's privileged control API. Compose runs
`containd all`; there is no Compose `CONTAIND_MODE` selector. For split deployments,
run `containd engine` and `containd mgmt` explicitly.

- Combined mode defaults to plaintext `127.0.0.1:8081`, without credentials.
  Leave `CONTAIND_ENGINE_URL` empty to derive it from `CONTAIND_ENGINE_ADDR`.
- Split engine mode has no default listener. Set `CONTAIND_ENGINE_ADDR` to the
  engine's interface-held management-network address, for example `10.10.0.2:8081`,
  and management's `CONTAIND_ENGINE_URL=https://10.10.0.2:8081`. Wildcard and
  loopback split binds are refused, except the
  [reserved management path](management-reservation.md), where both processes
  share a network namespace and require loopback.
- Any listener other than a **numeric loopback** IP requires mutual TLS: this
  includes wildcard, interface, scoped IPv6 and `localhost` binds. Name resolution
  never determines security. `127.0.0.0/8`, `::1` and mapped IPv4 loopback use HTTP.
  A wildcard combined bind derives an HTTPS loopback destination (same address
  family); an explicitly bound interface address remains the destination.
- `http://` remote targets, remote URLs without a scheme, credentials, paths
  (including a trailing slash), queries and fragments in engine URLs are refused.
  An explicit HTTP URL with a remote combined listener is a startup error.
  Management-only without an engine URL remains available without an engine.

#### Engine secret and rotation

Generate **one dedicated secret**, then supply the same value to both peers:

```sh
openssl rand -hex 32
# In each peer's private environment: CONTAIND_ENGINE_SECRET=<generated value>
```

The secret must encode 32 random bytes as 64 hex characters (case-insensitive,
outer whitespace trimmed). Blank, malformed and all-same-byte values are refused;
format validation cannot prove randomness. There is no `NGFW_` alias, lab bypass,
plaintext fallback or management JWT reuse. Starter/dev Compose pass the variable
through, including combined deployments with a non-loopback override.

TLS 1.3 and HTTP/1.1 protect **every** remote engine route, including `/health`,
`/readyz`, `/metrics`, telemetry and unknown paths. HKDF-SHA-256 with salt
`containd-engine-transport-v1` and separate `server-key`, `client-key`,
`server-serial`, `client-serial` labels derives Ed25519 identities. Fixed
self-signed certificates are identical on every host for the same secret.
The server has DNS identity `containd-engine`; each peer trusts only the other
role's derived certificate using standard X.509 verification. Certificates span
2020 through 9999: **rotation, not certificate expiry, revokes access**. Every
holder of the secret can act as either peer; this is not per-host PKI.

To rotate, change the secret on **both** peers and restart **both**. There is no
dual-secret window. Restart closes existing keep-alive connections. Regenerate
any exported scraper credentials too. A configured but unreachable engine keeps
the management retry/recovery path; authentication failures are logged.

#### Diagnostics and metrics credentials

Keep the engine network private; mutual TLS complements interface binding and
firewall admission, not replaces them. The supplied Compose files do not publish
an engine port. With the default listener, diagnostics are unchanged:

```sh
docker compose exec containd curl -s http://127.0.0.1:8081/health
```

For a remote listener, export credentials in an existing private directory with
`CONTAIND_ENGINE_SECRET` set in that process:

```sh
mkdir -m 700 engine-credentials
containd enginecredentials engine-credentials
```

This creates `server.crt`, `client.crt` and `client.key` (key mode 0600). Existing
files or symlinks are refused; any failure exits non-zero. Inspect partially
created files after failure and use a fresh directory to retry. **The client key
can call every engine route until rotation**, not just metrics. Keep it private.

Use a TLS 1.3, **OpenSSL-backed curl** (as shipped in the appliance image; check
`curl --version`). Do not disable certificate verification:

```sh
curl --cacert engine-credentials/server.crt \
  --cert engine-credentials/client.crt --key engine-credentials/client.key \
  --resolve containd-engine:8081:10.10.0.2 https://containd-engine:8081/health
```

Prometheus can use the same files; mount them read-only into the scraper:

```yaml
scrape_configs:
  - job_name: containd-engine
    scheme: https
    static_configs:
      - targets: ["10.10.0.2:8081"]
    tls_config:
      ca_file: /etc/prometheus/engine/server.crt
      cert_file: /etc/prometheus/engine/client.crt
      key_file: /etc/prometheus/engine/client.key
      server_name: containd-engine
```

### Low ports (DNS / DHCP)

Some appliance services traditionally bind to privileged ports (e.g. DNS on `53/udp,tcp`).

In Docker lab mode, `deploy/docker-compose.yml` grants `CAP_NET_BIND_SERVICE` and runs the appliance as `root` so embedded services can bind low ports and the dataplane can manage nftables, routing, and TUN devices reliably across Docker runtimes.

## Starter topology and interface mapping

The starter compose creates these Docker networks by default:

- `wan`: `192.168.240.0/24` (`192.168.240.2`)
- `dmz`: `192.168.241.0/24` (`192.168.241.2`)
- `lan1`: `192.168.242.0/24` (`192.168.242.2`)
- `lan2`: `192.168.243.0/24` (`192.168.243.2`)
- `lan3`: `192.168.244.0/24` (`192.168.244.2`)
- `lan4`: `192.168.245.0/24` (`192.168.245.2`)
- `lan5`: `192.168.246.0/24` (`192.168.246.2`)
- `lan6`: `192.168.247.0/24` (`192.168.247.2`)

Change the `CONTAIND_*_SUBNET` and `CONTAIND_*_IP` values in `.env` if your lab needs different addressing. The starter compose also marks `dmz` and `lan*` networks as Docker `internal` networks so they do not get accidental host NAT/external reachability by default.

### What Docker owns vs what containd owns

- Docker/Compose owns: which networks exist, which containers attach to them, and the container-level IP layout on those networks.
- containd owns: zone assignment, firewall rules, NAT, services, DPI, routing intent, and segmentation for traffic that is actually routed through the appliance.

If you want a workload to be segmented by containd, attach it to a single zone network and route cross-zone traffic through containd. If you multi-home an application container directly onto multiple zone networks, Docker gives it its own bypass path.

For larger classroom or demo environments, see [Customizing Lab Compose](lab-compose.md).
For Docker Desktop on Windows specifically, see [Windows / WSL Notes](windows-wsl.md).

### Logical roles and kernel devices

When the `containd` service is attached to multiple Docker networks, Docker creates one kernel interface per network.
The kernel device names (`eth0`, `eth1`, …) are not guaranteed to correspond to `wan/dmz/lan1…` in a stable order,
because Docker network attach order can vary.

In this repo’s `deploy/docker-compose.yml`, we explicitly pin:
- `wan` as the default-gateway network (`gw_priority`) so the kernel default route is via WAN.
- stable per-network subnets and IPs so `Interfaces -> Auto-assign` can map `wan/dmz/lan1..lan6` deterministically even on Docker engines that do not support network-level `interface_name`.

To keep the appliance UI/CLI stable in Docker labs, `Interfaces → Auto-assign` prefers matching interface roles by
the IPv4 subnets present on each interface (defaults match this repo’s `deploy/docker-compose.yml`):

- `wan`: `192.168.240.0/24`
- `dmz`: `192.168.241.0/24`
- `lan1..lan6`: `192.168.242.0/24` … `192.168.247.0/24`

An explicit `CONTAIND_AUTO_<NAME>_SUBNET` hint takes precedence over
`CONTAIND_<NAME>_SUBNET`. A missing or ambiguous match under either explicit
authority leaves that role unbound; there is no name, default-route, or index
fallback. Only roles without explicit authority can use those heuristics after
subnet matching. The starter supplies explicit topology subnets for all eight roles.

On newer Docker engines you can optionally use Compose `interface_name` in custom lab files, but the supported starter path avoids depending on it so it works across older GitHub runners and classroom Docker installs.

To override subnet matching (for custom lab topologies), set:
`CONTAIND_AUTO_WAN_SUBNET`, `CONTAIND_AUTO_DMZ_SUBNET`, `CONTAIND_AUTO_LAN1_SUBNET` … `CONTAIND_AUTO_LAN6_SUBNET`.
These optional overrides are only for the eight default roles. Normally leave
them unset: matching already uses the corresponding topology subnet variable.
If you set an AUTO override, keep it aligned with the intended network.

### Ports

- `CONTAIND_PUBLISH_HTTP_PORT`: host port for HTTP UI/API → container `8080`.
- `CONTAIND_PUBLISH_HTTPS_PORT`: host port for HTTPS UI/API → container `8443`.
- `CONTAIND_PUBLISH_SSH_PORT`: host port for SSH → container `2222`.
- Engine port `8081` is never published. See the trust boundary and in-container
  diagnostics above.

Smoke harness: `deploy/docker-compose.smoke.yml` drives the mgmt API on host `18080` to avoid collisions; the smoke scripts call the engine API inside the container with `docker compose exec`.

### Persistent data paths (inside container)

All default DB paths are under `/data`:

- `CONTAIND_CONFIG_DB` (default `/data/config.db`)
- `CONTAIND_AUDIT_DB` (default `/data/audit.db`)
- `CONTAIND_USERS_DB` (default `/data/users.db`)
- `CONTAIND_EVIDENCE_DB` (engine-owned evidence, default `/data/evidence.db`)

The starter and dev Compose files pass through the first three variables.
To override the evidence path, add `CONTAIND_EVIDENCE_DB` to the service's
`environment` as well; setting it only in `.env` does not pass it into the container.

The bind-mount source depends on the Compose file location:

| Layout | Host directory backing `/data` |
| --- | --- |
| Bootstrapped starter | `data/` beside the downloaded `docker-compose.yml` |
| Repository starter (`deploy/docker-compose.yml`) | `deploy/data/` |
| Repository dev (`deploy/docker-compose.dev.yml`) | repository-root `data/` |

Back up the directory for the layout you actually run, not an unrelated `data/`.

The starter and dev Compose files also mount the named volume `clamav-db` on
`/var/lib/clamav`, so the official ClamAV databases survive container
replacement instead of being downloaded again. In a split deployment, mount a
volume there on the engine service. It holds no configuration and need not be
backed up; `docker compose down -v` removes it.

### SSH bootstrap

To avoid “chicken/egg” provisioning, you can seed an admin SSH key (authorized_keys line):

- `CONTAIND_SSH_BOOTSTRAP_ADMIN_KEY`
- `CONTAIND_SSH_BOOTSTRAP_ADMIN_USER` (default `containd`)

## Troubleshooting

- Validate compose: `docker compose config -q`
- Validate the repo-local starter path: `docker compose --env-file .env -f deploy/docker-compose.yml config -q`
- Follow logs: `docker compose logs -f containd`
- If a save succeeds but the UI shows a warning banner, Docker likely owns the underlying interface or route state. Adjust the topology/IP layout in `.env` or `docker-compose.yml`, then use containd for zones and policy on top of it.
- If interface auto-assign/reconcile fails with `engine interfaces status 400`, check `docker compose logs -f containd` for the underlying runtime error.
- If temporary block actions are unavailable, verify dataplane enforcement is enabled in the config model and that your compose file is passing `CONTAIND_ENFORCE_ENABLED=1`.
- If you see `operation not permitted` for WireGuard, OpenVPN TUN setup, or routing changes, verify the Docker runtime still has the expected capabilities/devices (`NET_ADMIN`, `NET_RAW`, `/dev/net/tun`) and that Windows is using the WSL2-backed Docker Desktop path.
- Factory reset (CLI): `factory reset NUCLEAR` (admin only; wipes config/users/audit and re-seeds defaults)
