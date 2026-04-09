# SPDX – External Components

This file tracks third‑party/external components that containd embeds, vendors, or relies on at runtime **as part of the appliance**, along with their SPDX license identifiers.

**Process**
- Update this file whenever a new external component is added, removed, or swapped.
- Prefer SPDX identifiers from https://spdx.org/licenses/.
- If a component has multiple valid licenses, list the one we are using and note the alternative.
- Keep this list aligned with actual build/runtime packaging.
- This list is intentionally **not exhaustive** for every transitive Go/npm dependency; use `go.mod` and `ui/package.json` for the complete dependency graphs.

---

## Runtime/Embedded Components (In Use)

| Component | Purpose | SPDX License | Notes |
|---|---|---|---|
| Go (stdlib) | Control/data/mgmt plane binaries | BSD-3-Clause | Go runtime/stdlib is compiled into `containd` (we do not ship the Go toolchain in the image). |
| Gin | REST API framework | MIT | Used in `api/http`. |
| `github.com/golang-jwt/jwt/v5` | JWT auth | MIT | Used for UI/API auth sessions. |
| `github.com/prometheus/client_golang` | Prometheus metrics | Apache-2.0 | Exposes `/metrics` endpoint for monitoring. |
| `modernc.org/sqlite` | Embedded SQLite (Go) | BSD-3-Clause | Used for config/audit/users DBs. |
| Next.js | Web UI framework | MIT | UI is built as a static export and embedded in the mgmt image. |
| React | UI library | MIT | Via Next.js. |
| Tailwind CSS | UI styling | MIT | Built into UI assets. |
| Envoy Proxy | Optional explicit forward proxy | Apache-2.0 | Copied into the mgmt appliance image from `envoyproxy/envoy`. |
| Nginx | Optional reverse proxy | BSD-2-Clause | Copied into the mgmt appliance image from `nginxinc/nginx-unprivileged`. |
| Unbound | DNS caching/forwarding resolver | BSD-3-Clause | Embedded in the mgmt image (forwarder-first config; supervised by `containd mgmt`). |
| OpenNTPD | NTP client | ISC | Embedded in the mgmt image; supervised by `containd mgmt` when enabled. |
| WireGuard (Linux kernel) | Remote access VPN dataplane | GPL-2.0-only | WireGuard runs via Linux kernel interfaces + generic netlink control; we do not bundle the `wg` CLI in the appliance image. |
| OpenVPN | Compatibility VPN | GPL-2.0-only WITH OpenSSL-exception | Embedded in the mgmt image; supervised by `containd mgmt` when enabled with a foreground config (no `daemon`). |
| xterm.js | In-app terminal emulator | MIT | Used by the in-app console UI (`ui/components/Console.tsx`). |
| nftables (`nft`) | Kernel firewall programming | GPL-2.0-or-later | Userspace `nft` binary is copied into the engine image from Debian packages. |
| ClamAV | Antivirus scanning (ICAP pipeline) | GPL-2.0-only | Embedded `clamd`/`freshclam` binaries; executed as separate processes, not linked into `containd`. |
| tini | PID 1 init | MIT | Lightweight init for the mgmt container entrypoint. |
| React Flow | Topology UI | MIT | Used for topology/graph screens in the UI. |
| Recharts | Charts | MIT | Used for dashboard charts and sparklines. |
| Wolfi base (`cgr.dev/chainguard/wolfi-base`) | Minimal glibc runtime base | Apache-2.0 | Used as the final base image for mgmt/engine containers. |

---

## Build/Documentation Tooling (Not Shipped In Appliance Image)

These are used to build UI/docs (CI/Docker build stages), but are not included in the final runtime image.

| Component | Purpose | SPDX License | Notes |
|---|---|---|---|
| MkDocs | Documentation build | BSD-2-Clause | Builds docs from `docs/mkdocs/`. |
| Material for MkDocs | Docs theme | MIT | Used for navigation/search/admonitions. |
| pymdown-extensions | Markdown extensions | MIT | Enables advanced admonitions/code fences. |
| Node.js | UI build toolchain | MIT | Used in Docker UI build stage. |
| Python | Docs build toolchain | PSF-2.0 | Used in Docker docs build stage. |

