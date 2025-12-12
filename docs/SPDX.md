# SPDX – External Components

This file tracks third‑party/external components that containd embeds, vendors, or relies on at runtime **as part of the appliance**, along with their SPDX license identifiers.

**Process**
- Update this file whenever a new external component is added, removed, or swapped.
- Prefer SPDX identifiers from https://spdx.org/licenses/.
- If a component has multiple valid licenses, list the one we are using and note the alternative.
- Keep this list aligned with `agents.md` and actual build/runtime packaging.

---

## Runtime/Embedded Components (Planned or In Use)

| Component | Purpose | SPDX License | Notes |
|---|---|---|---|
| Go (toolchain/runtime) | Control/data/mgmt plane binaries | BSD-3-Clause | Go standard library is BSD‑3‑Clause; toolchain also includes other permissive notices. |
| Gin | REST API framework | MIT | Used in `api/http`. |
| Next.js | Web UI framework | MIT | Static export embedded in mgmt image. |
| React | UI library | MIT | Via Next.js. |
| Tailwind CSS | UI styling | MIT | Via Next.js build. |
| Envoy Proxy | Explicit forward proxy | Apache-2.0 | Replaces Squid to avoid copyleft. |
| Nginx | Reverse proxy / L7 publishing | BSD-2-Clause | Standardize on Nginx for v1. |
| Zeek | Optional IT/ICS DPI + telemetry | BSD-3-Clause | Optional; must be lifecycle‑managed and normalized. |
| Unbound | DNS caching/forwarding resolver | BSD-3-Clause | Appliance‑friendly resolver choice. |
| OpenNTPD | NTP client | ISC | Permissive alternative to Chrony. |

---

## Future Candidates (Not Yet Adopted)

| Component | Purpose | SPDX License | Notes |
|---|---|---|---|
| xterm.js | Web UI console | MIT | If/when we add in‑UI CLI console. |
| React Flow | Topology UI | MIT | Planned for topology/graph screens. |
| Recharts | Charts | MIT | Candidate for dashboards. |

---

## Removed / Rejected (License Reasons)

| Component | Purpose | SPDX License | Reason |
|---|---|---|---|
| Squid | Forward proxy | GPL-2.0-only | Removed to avoid copyleft obligations. |
| Suricata | IDS/IPS signatures | GPL-2.0-only | Removed to avoid copyleft obligations. |
| Chrony | NTP client | GPL-2.0-only | Removed to avoid copyleft obligations. |

