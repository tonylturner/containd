# Control plane and management maturity audit

Target: `iec104` @ `40ec7f81` (2026-10-25). Read-only source audit for training and containerized industrial-firewall maturity; not a physical appliance certification. Prior incomplete report was read; its backup, transaction, apply-state, staged-secret and audit findings were independently verified and carried forward (F4/F5/F7/F14/F15). **Verified** means inspected implementation (not a runtime guarantee); **Inferred** identifies consequences/design gaps; **Open** requires follow-up. No source changes, Docker, broad tests, or UI sessions.

Exclusions: Store.Save overwriting running, reserved management path, rule-save/commit UX, base-path icons, and IEC104 monitor expansion are **in progress elsewhere**, not new findings here. Release version remains 0.1.32, next 0.1.33.

## 1. Inventory

_Report assembled incrementally from source, documentation, UI/CLI contracts and three targeted tests._

### Core management surfaces (Verified)
- Persistent typed config covers system/listeners/SSH, interfaces/zones/assets/objects/routing, dataplane/export/PCAP, firewall/NAT/IDS and services (`pkg/cp/config/config.go:14-30`). SQLite separates running/candidate/previous/pending and IDS rules (`store.go:24-47,135-153`); candidate is globally shared and lazily seeded (`239-272`). Schema version is 0.1.7, independent of release; upgrade accepts older same-major/minor patch versions by bumping the version (`version.go:13,76-105`).
- Candidate save/read/diff, commit, commit-confirmed, confirmation and rollback exist in API (`api/http/server.go:227-242,437-553`) and CLI (`pkg/cli/registry.go:140-145`). Timed rollback survives restart and notifies management for runtime replay (`pkg/cp/config/store.go:416-451,549-568`; `pkg/app/mgmt/engine_sync.go:46-69,85-90`). This is real functionality, not a stub.
- Import/export and named local backups are implemented (`api/http/config_backup_handlers.go:27-90,172-385`). Redacted export defaults on; unredacted export/download requires admin (`38-56,342-345`). Backups are config JSON + metadata + local IDS sidecar, not full-instance archives.
- API router centralizes management authorization (`api/http/server.go:196-384`): health and metrics public; login/MFA/logout public; remaining routes authenticated; mutators mostly explicitly admin. Auth has session JWT + SQLite session/user revalidation, legacy tokens and explicit lab mode (`api/http/auth.go:45-147,193-267`). HTTP self-service account/MFA is role-independent; users administration is admin-only. Roles are only admin/view, not per-resource permissions.
- Shared appliance CLI covers telemetry, policy/routing/NAT, templates, syslog, configuration lifecycle and local network diagnostics (`pkg/cli/registry.go:29-149`); HTTP execute/completion/WebSocket delegate to it (`api/http/cli_handlers.go:26-164`). Command role checks are real (`pkg/cli/registry.go:177-193`).
- Audit SQLite has actor/source/action/target/result/detail, newest-first limit/offset listing, no server-side filters (`pkg/cp/audit/store.go:69-128`; `api/http/audit.go:17-44`). HTTP audit integration is explicit per-handler, best effort (`api/http/server.go:717-765`).
- Built-in policy registry plus seven parameterized ICS templates support learn/enforce, preview and zone substitution (`pkg/cp/templates/templates.go:13-94`; `api/http/template_identity_handlers.go:69-231`). General template apply skips colliding IDs; ICS apply upserts colliding IDs; no durable template provenance/version is in the model.
- Services manager renders and supervises DNS Unbound, NTP chrony/openntpd, Envoy/Nginx proxies, OpenVPN; config-render manager for engine DHCP/WireGuard; ICAP/ClamAV scanner and freshclam (`pkg/cp/services/manager.go:54-114,213-310`; individual managers below). Initial service apply and engine restart replay exist (`pkg/app/mgmt/mgmt.go:80-107`).

### Endpoint-by-endpoint authorization inventory (Verified static routing)

All following rows are from `api/http/server.go`; line numbers below refer to that file. This is a registration review, **not** a claim of executing a complete endpoint authorization matrix. Conditional `/audit` registration adds authenticated GET (`api/http/audit.go:17`); optional identity routes are included. Public static UI assets are not API authorization boundaries. `view` can read network topology, audit and PCAPs; this is the current coarse policy, not an accidental missing admin check.

| Method | Path | Policy | Line |
|---|---|---|---|
| GET | `/api/v1/health` | public | 199 |
| GET | `/metrics` | public | 201 |
| POST | `/api/v1/auth/login` | public | 203 |
| POST | `/api/v1/auth/login/mfa` | public | 204 |
| POST | `/api/v1/auth/logout` | public | 207 |
| GET | `/api/v1/auth/me` | authenticated (admin/view); self only | 213 |
| GET | `/api/v1/auth/session` | authenticated (admin/view) | 214 |
| PATCH | `/api/v1/auth/me` | authenticated (admin/view); self only | 215 |
| POST | `/api/v1/auth/me/password` | authenticated (admin/view); self only | 216 |
| POST | `/api/v1/auth/me/mfa/enroll` | authenticated (admin/view); self only | 217 |
| POST | `/api/v1/auth/me/mfa/enable` | authenticated (admin/view); self only | 218 |
| POST | `/api/v1/auth/me/mfa/disable` | authenticated (admin/view); self only | 219 |
| GET | `/api/v1/dashboard` | authenticated (admin/view) | 220 |
| GET | `/api/v1/system/stats` | authenticated (admin/view) | 221 |
| GET | `/api/v1/system/inspection` | authenticated (admin/view) | 222 |
| GET | `/api/v1/system/tls` | authenticated (admin/view) | 223 |
| POST | `/api/v1/system/tls/cert` | admin | 224 |
| POST | `/api/v1/system/tls/trusted-ca` | admin | 225 |
| POST | `/api/v1/system/factory-reset` | admin | 226 |
| GET | `/api/v1/config` | authenticated (admin/view) | 227 |
| POST | `/api/v1/config` | admin | 228 |
| POST | `/api/v1/config/validate` | admin | 229 |
| GET | `/api/v1/config/export` | authenticated (admin/view); secret gate in handler | 230 |
| POST | `/api/v1/config/import` | admin | 231 |
| GET | `/api/v1/config/candidate` | authenticated (admin/view) | 232 |
| POST | `/api/v1/config/candidate` | admin | 233 |
| GET | `/api/v1/config/diff` | authenticated (admin/view) | 234 |
| GET | `/api/v1/config/backups` | authenticated (admin/view); secret gate in handler | 235 |
| POST | `/api/v1/config/backups` | admin | 236 |
| GET | `/api/v1/config/backups/:id` | authenticated (admin/view); secret gate in handler | 237 |
| DELETE | `/api/v1/config/backups/:id` | admin | 238 |
| POST | `/api/v1/config/commit` | admin | 239 |
| POST | `/api/v1/config/commit_confirmed` | admin | 240 |
| POST | `/api/v1/config/confirm` | admin | 241 |
| POST | `/api/v1/config/rollback` | admin | 242 |
| GET | `/api/v1/services/syslog` | authenticated (admin/view) | 243 |
| POST | `/api/v1/services/syslog` | admin | 244 |
| PATCH | `/api/v1/services/syslog` | admin | 245 |
| GET | `/api/v1/services/dns` | authenticated (admin/view) | 246 |
| POST | `/api/v1/services/dns` | admin | 247 |
| GET | `/api/v1/services/ntp` | authenticated (admin/view) | 248 |
| POST | `/api/v1/services/ntp` | admin | 249 |
| GET | `/api/v1/services/dhcp` | authenticated (admin/view) | 250 |
| POST | `/api/v1/services/dhcp` | admin | 251 |
| GET | `/api/v1/services/vpn` | authenticated (admin/view) | 252 |
| POST | `/api/v1/services/vpn` | admin | 253 |
| POST | `/api/v1/services/vpn/openvpn/profile` | admin | 254 |
| GET | `/api/v1/services/vpn/openvpn/clients` | admin | 255 |
| POST | `/api/v1/services/vpn/openvpn/clients` | admin | 256 |
| GET | `/api/v1/services/vpn/openvpn/clients/:name` | admin | 257 |
| GET | `/api/v1/services/vpn/wireguard/status` | authenticated (admin/view) | 258 |
| GET | `/api/v1/services/av` | authenticated (admin/view) | 259 |
| POST | `/api/v1/services/av` | admin | 260 |
| POST | `/api/v1/services/av/update` | admin | 261 |
| GET | `/api/v1/services/av/defs` | authenticated (admin/view) | 262 |
| POST | `/api/v1/services/av/defs` | admin | 263 |
| DELETE | `/api/v1/services/av/defs` | admin | 264 |
| GET | `/api/v1/services/proxy/forward` | authenticated (admin/view) | 265 |
| POST | `/api/v1/services/proxy/forward` | admin | 266 |
| GET | `/api/v1/services/proxy/reverse` | authenticated (admin/view) | 267 |
| POST | `/api/v1/services/proxy/reverse` | admin | 268 |
| GET | `/api/v1/services/status` | authenticated (admin/view) | 269 |
| GET | `/api/v1/events` | authenticated (admin/view) | 270 |
| GET | `/api/v1/events/:id` | authenticated (admin/view) | 271 |
| GET | `/api/v1/flows` | authenticated (admin/view) | 272 |
| GET | `/api/v1/simulation` | authenticated (admin/view) | 273 |
| POST | `/api/v1/simulation` | admin | 274 |
| GET | `/api/v1/stats/protocols` | authenticated (admin/view) | 275 |
| GET | `/api/v1/stats/top-talkers` | authenticated (admin/view) | 276 |
| GET | `/api/v1/anomalies` | authenticated (admin/view) | 277 |
| DELETE | `/api/v1/anomalies` | admin | 278 |
| GET | `/api/v1/conntrack` | authenticated (admin/view) | 279 |
| POST | `/api/v1/conntrack/kill` | admin | 280 |
| GET | `/api/v1/dhcp/leases` | authenticated (admin/view) | 281 |
| GET | `/api/v1/dataplane` | authenticated (admin/view) | 282 |
| POST | `/api/v1/dataplane` | admin | 283 |
| GET | `/api/v1/dataplane/ruleset` | admin | 284 |
| POST | `/api/v1/dataplane/blocks/host` | admin | 285 |
| POST | `/api/v1/dataplane/blocks/flow` | admin | 286 |
| GET | `/api/v1/pcap/config` | authenticated (admin/view) | 287 |
| POST | `/api/v1/pcap/config` | admin | 288 |
| POST | `/api/v1/pcap/start` | admin | 289 |
| POST | `/api/v1/pcap/stop` | admin | 290 |
| GET | `/api/v1/pcap/status` | authenticated (admin/view) | 291 |
| GET | `/api/v1/pcap/list` | authenticated (admin/view) | 292 |
| POST | `/api/v1/pcap/upload` | admin | 293 |
| GET | `/api/v1/pcap/download/:name` | authenticated (admin/view) | 294 |
| DELETE | `/api/v1/pcap/:name` | admin | 295 |
| POST | `/api/v1/pcap/tag` | admin | 296 |
| POST | `/api/v1/pcap/replay` | admin | 297 |
| POST | `/api/v1/pcap/analyze` | admin | 298 |
| POST | `/api/v1/pcap/analyze/:name` | admin | 299 |
| GET | `/api/v1/inventory` | authenticated (admin/view) | 300 |
| GET | `/api/v1/inventory/:ip` | authenticated (admin/view) | 301 |
| DELETE | `/api/v1/inventory` | admin | 302 |
| GET | `/api/v1/signatures` | authenticated (admin/view) | 303 |
| POST | `/api/v1/signatures` | admin | 304 |
| DELETE | `/api/v1/signatures/:id` | admin | 305 |
| GET | `/api/v1/signatures/matches` | authenticated (admin/view) | 306 |
| GET | `/api/v1/assets` | authenticated (admin/view) | 307 |
| POST | `/api/v1/assets` | admin | 308 |
| PATCH | `/api/v1/assets/:id` | admin | 309 |
| DELETE | `/api/v1/assets/:id` | admin | 310 |
| GET | `/api/v1/objects` | authenticated (admin/view) | 311 |
| POST | `/api/v1/objects` | admin | 312 |
| PATCH | `/api/v1/objects/:id` | admin | 313 |
| DELETE | `/api/v1/objects/:id` | admin | 314 |
| GET | `/api/v1/zones` | authenticated (admin/view) | 315 |
| POST | `/api/v1/zones` | admin | 316 |
| PATCH | `/api/v1/zones/:name` | admin | 317 |
| DELETE | `/api/v1/zones/:name` | admin | 318 |
| GET | `/api/v1/interfaces` | authenticated (admin/view) | 319 |
| GET | `/api/v1/interfaces/state` | authenticated (admin/view) | 320 |
| POST | `/api/v1/interfaces/assign` | admin | 321 |
| POST | `/api/v1/interfaces/reconcile` | admin | 322 |
| POST | `/api/v1/interfaces` | admin | 323 |
| PATCH | `/api/v1/interfaces/:name` | admin | 324 |
| DELETE | `/api/v1/interfaces/:name` | admin | 325 |
| GET | `/api/v1/routing` | authenticated (admin/view) | 326 |
| GET | `/api/v1/routing/os` | authenticated (admin/view) | 327 |
| POST | `/api/v1/routing` | admin | 328 |
| POST | `/api/v1/routing/reconcile` | admin | 329 |
| GET | `/api/v1/firewall/nat` | authenticated (admin/view) | 330 |
| POST | `/api/v1/firewall/nat` | admin | 331 |
| GET | `/api/v1/firewall/rules` | authenticated (admin/view) | 332 |
| POST | `/api/v1/firewall/rules` | admin | 333 |
| PATCH | `/api/v1/firewall/rules/:id` | admin | 334 |
| DELETE | `/api/v1/firewall/rules/:id` | admin | 335 |
| POST | `/api/v1/firewall/rules/preview` | admin | 336 |
| GET | `/api/v1/firewall/ics-rules` | authenticated (admin/view) | 337 |
| POST | `/api/v1/firewall/ics-rules` | admin | 338 |
| PATCH | `/api/v1/firewall/ics-rules/:id` | admin | 339 |
| GET | `/api/v1/learn/profiles` | authenticated (admin/view) | 341 |
| POST | `/api/v1/learn/generate` | admin | 342 |
| POST | `/api/v1/learn/apply` | admin | 343 |
| DELETE | `/api/v1/learn` | admin | 344 |
| GET | `/api/v1/security/conduits` | authenticated (admin/view) | 345 |
| GET | `/api/v1/ids/rules` | authenticated (admin/view) | 346 |
| POST | `/api/v1/ids/rules` | admin | 347 |
| POST | `/api/v1/ids/convert/sigma` | authenticated (admin/view) | 348 |
| POST | `/api/v1/ids/import` | admin | 349 |
| POST | `/api/v1/ids/export` | authenticated (admin/view) | 350 |
| GET | `/api/v1/ids/sources` | authenticated (admin/view) | 351 |
| GET | `/api/v1/ids/backup` | authenticated (admin/view) | 352 |
| POST | `/api/v1/ids/restore` | admin | 353 |
| POST | `/api/v1/cli/execute` | authenticated (admin/view); command RBAC + downstream API | 354 |
| GET | `/api/v1/cli/commands` | authenticated (admin/view) | 355 |
| GET | `/api/v1/cli/complete` | authenticated (admin/view) | 356 |
| GET | `/api/v1/cli/ws` | authenticated (admin/view); command RBAC + downstream API | 357 |
| GET | `/api/v1/users` | admin | 359 |
| POST | `/api/v1/users` | admin | 360 |
| PATCH | `/api/v1/users/:id` | admin | 361 |
| POST | `/api/v1/users/:id/password` | admin | 362 |
| POST | `/api/v1/users/:id/mfa/disable` | admin | 363 |
| POST | `/api/v1/users/:id/mfa/require` | admin | 364 |
| POST | `/api/v1/users/:id/mfa/clear` | admin | 365 |
| POST | `/api/v1/users/:id/mfa/grace` | admin | 366 |
| DELETE | `/api/v1/users/:id` | admin | 367 |
| GET | `/api/v1/templates` | authenticated (admin/view) | 372 |
| POST | `/api/v1/templates/apply` | admin | 373 |
| GET | `/api/v1/templates/ics` | authenticated (admin/view) | 375 |
| POST | `/api/v1/templates/ics/apply` | admin | 376 |
| GET | `/api/v1/identities` | authenticated (admin/view) | 380 |
| POST | `/api/v1/identities` | admin | 381 |
| DELETE | `/api/v1/identities/:ip` | admin | 382 |

### OpenAPI operation census (Verified static comparison)

`server.go` registers 165 method/path pairs (164 under `/api/v1`); OpenAPI describes 66 operations. 101 registered versioned operations are undocumented; `/audit` is separately documented and registered conditionally. 3 spec operations are absent from `server.go` (including that conditional audit route). No claim of schema compatibility follows from route matching.

Undocumented registered operations: `DELETE /api/v1/anomalies`, `DELETE /api/v1/assets/{id}`, `DELETE /api/v1/config/backups/{id}`, `DELETE /api/v1/identities/{ip}`, `DELETE /api/v1/interfaces/{name}`, `DELETE /api/v1/inventory`, `DELETE /api/v1/objects/{id}`, `DELETE /api/v1/pcap/{name}`, `DELETE /api/v1/services/av/defs`, `DELETE /api/v1/zones/{name}`, `GET /api/v1/assets`, `GET /api/v1/auth/session`, `GET /api/v1/cli/commands`, `GET /api/v1/cli/complete`, `GET /api/v1/cli/ws`, `GET /api/v1/config/backups`, `GET /api/v1/config/backups/{id}`, `GET /api/v1/config/diff`, `GET /api/v1/config/export`, `GET /api/v1/conntrack`, `GET /api/v1/dataplane`, `GET /api/v1/dataplane/ruleset`, `GET /api/v1/dhcp/leases`, `GET /api/v1/events/{id}`, `GET /api/v1/firewall/ics-rules`, `GET /api/v1/firewall/nat`, `GET /api/v1/identities`, `GET /api/v1/ids/backup`, `GET /api/v1/ids/rules`, `GET /api/v1/ids/sources`, `GET /api/v1/interfaces`, `GET /api/v1/interfaces/state`, `GET /api/v1/inventory/{ip}`, `GET /api/v1/objects`, `GET /api/v1/pcap/download/{name}`, `GET /api/v1/pcap/list`, `GET /api/v1/routing`, `GET /api/v1/routing/os`, `GET /api/v1/security/conduits`, `GET /api/v1/services/av`, `GET /api/v1/services/av/defs`, `GET /api/v1/services/proxy/forward`, `GET /api/v1/services/proxy/reverse`, `GET /api/v1/services/status`, `GET /api/v1/services/vpn/openvpn/clients`, `GET /api/v1/services/vpn/openvpn/clients/{name}`, `GET /api/v1/services/vpn/wireguard/status`, `GET /api/v1/simulation`, `GET /api/v1/system/inspection`, `GET /api/v1/system/stats`, `GET /api/v1/system/tls`, `GET /api/v1/templates`, `GET /api/v1/zones`, `PATCH /api/v1/assets/{id}`, `PATCH /api/v1/firewall/ics-rules/{id}`, `PATCH /api/v1/interfaces/{name}`, `PATCH /api/v1/objects/{id}`, `PATCH /api/v1/services/syslog`, `PATCH /api/v1/zones/{name}`, `POST /api/v1/assets`, `POST /api/v1/auth/me/password`, `POST /api/v1/cli/execute`, `POST /api/v1/config/backups`, `POST /api/v1/config/commit_confirmed`, `POST /api/v1/config/confirm`, `POST /api/v1/config/validate`, `POST /api/v1/conntrack/kill`, `POST /api/v1/dataplane`, `POST /api/v1/dataplane/blocks/flow`, `POST /api/v1/dataplane/blocks/host`, `POST /api/v1/firewall/ics-rules`, `POST /api/v1/firewall/nat`, `POST /api/v1/identities`, `POST /api/v1/ids/convert/sigma`, `POST /api/v1/ids/export`, `POST /api/v1/ids/import`, `POST /api/v1/ids/restore`, `POST /api/v1/ids/rules`, `POST /api/v1/interfaces`, `POST /api/v1/interfaces/assign`, `POST /api/v1/interfaces/reconcile`, `POST /api/v1/objects`, `POST /api/v1/pcap/replay`, `POST /api/v1/pcap/tag`, `POST /api/v1/pcap/upload`, `POST /api/v1/routing`, `POST /api/v1/routing/reconcile`, `POST /api/v1/services/av`, `POST /api/v1/services/av/defs`, `POST /api/v1/services/av/update`, `POST /api/v1/services/proxy/forward`, `POST /api/v1/services/proxy/reverse`, `POST /api/v1/services/vpn/openvpn/clients`, `POST /api/v1/services/vpn/openvpn/profile`, `POST /api/v1/simulation`, `POST /api/v1/system/factory-reset`, `POST /api/v1/system/tls/cert`, `POST /api/v1/system/tls/trusted-ca`, `POST /api/v1/templates/apply`, `POST /api/v1/users/{id}/password`, `POST /api/v1/zones`.

Spec-only operations versus facade: `GET /api/v1/audit` (OpenAPI:1073), `GET /api/v1/engine/config` (OpenAPI:1321), `POST /api/v1/engine/config` (OpenAPI:1330).

### UI, CLI, documentation, tests and deployment inventory (Verified)
- UI config explorer/editor/diff, confirmation dialogs, timed-commit TTL entry, export/upload restore and local backup list/create/download/delete: `ui/app/config/page.tsx:41-275`, `config-overview-panels.tsx`. IDS has a separate backup/restore client (`ui/lib/api-config.ts:42-54`). No API returns pending-confirmed deadline/owner/revision, so the UI cannot recover authoritative timer state after reload (`config.Store`, `server.go:227-242`).
- Service overview and per-service forms: `ui/app/system/services/page.tsx:15-66`, `dns/page.tsx:16-84`, `ntp/page.tsx:14-79`, `syslog/page.tsx:14-108`, `av/page.tsx:17-141`; DHCP pools/reservations/leases (`ui/app/dhcp/page.tsx:17-120`), proxies (`ui/app/proxies/page.tsx:24-194`), VPN editors and runtime status (`ui/app/vpn/*`). Forms hide/disable edits using local stored role; **backend role enforcement**, not localStorage, is the security boundary (`ui/lib/api-core.ts:85-98`; API inventory above).
- Audit UI loads one API page then searches/sorts/paginates locally (`ui/app/audit/page.tsx:15-34,99`; `ui/lib/api-policy.ts:100`). Templates UI has seven ICS options, preview/apply modal and zone selectors (`ui/app/templates/page.tsx:118-134,245-291`). TLS certificate/private-key and outbound CA uploads exist under settings (`ui/app/system/settings/page.tsx:51-84,126-175`); user CRUD/MFA administration is in `ui/app/system/users/page.tsx` with server handlers `api/http/users_handlers.go` / `auth_mfa.go`.
- Shared UI request layer surfaces warning headers for mutations (`ui/lib/api-request.ts:119-146`); reads instead collapse HTTP/network failures to null (`10-30`). Monitoring page polls flows/events/services (`ui/app/monitoring/page.tsx:17-43`). No central/fleet page or multi-device API client exists; client base URL selects one instance (`ui/lib/api-core.ts:1-18`).
- SSH is admin-only at password/public-key login, issues an HTTP session and shares CLI; native shell is available to PTY sessions (`pkg/mp/sshserver/server_auth.go:58-112,140-160`; `server.go:169-202,251-259,329-334`). No SRA broker, approvals or time-bound scoped roles are represented in this control-plane model; coordinate the SRA audit for deeper transport/session design.
- Operator docs examined: `docs/mkdocs/config-format.md` (model/endpoints), `services.md` (service runtime), `cli.md` (command/auth semantics), `api-reference.md` (OpenAPI, environment, retention/warnings), `logging-evidence.md` (administrative/off-box evidence), `update-policy.md` (manual signed-image upgrade and `/data` preservation), `secure-by-design.md` (roadmap). Architecture/conventions: `CONTRIBUTING.md`, `docs/mkdocs/code-boundaries.md`, `api/http/README.md`; `pkg/cli/README.md:5` still calls the implemented CLI a placeholder.
- Tests inspected: config save/load/validation/candidate/rollback/confirmed timer/restart notification (`pkg/cp/config/store_test.go:17-397`); auth session/revocation/self-service/last-admin/RBAC (`api/http/handlers_auth_test.go:21-708`), MFA (`handlers_auth_mfa_test.go`), route sanity (`route_inventory_test.go:144-177`), apply serialization (`running_config_apply_test.go:53-268`), backup path safety (`handlers_test.go:496-532`), CLI execute/completion/WebSocket (`cli_handlers_test.go:20-168`), service renderer/protocol/cache/process tests (`pkg/cp/services/*_test.go`). These exist but do not establish the fault/recovery/protocol properties flagged below. Route inventory uses admin requests and accepts 501/503; it is not an all-role endpoint contract suite.
- Upgrades are operator-driven image replacement with signed images/SBOM/digest guidance, not an in-application updater (`docs/mkdocs/update-policy.md:29-53`). Three separate SQLite stores plus `/data` certificate/profile/definition files require volume-level recovery (`pkg/app/mgmt/mgmt.go:143-150`; `store_helpers.go:25-88`). `UpgradeInPlace` is currently a patch-version bump, not a migration registry. No config revision log, per-instance policy targets, controller/agent enrollment, replication, leader election or coordinated rollout is present in the inspected model/store/router/client. This is appropriate for an initial single-lab appliance but not mature centralized operation (absence claim bounded to inspected surfaces).

### Documentation, UI and test coverage map (Verified source)
- User workflows: config JSON/diff/backups/confirmed controls (`ui/app/config/page.tsx:41-175,288-338`), templates (`ui/app/templates/page.tsx:27-114,256-262,405-463`), audit (`ui/app/audit/page.tsx:15-34,99`), DHCP (`ui/app/dhcp/page.tsx:17-27,78-94`), DNS/NTP/syslog/AV and service overview (`ui/app/system/services/*/page.tsx`; findings below), TLS/trust (`ui/app/system/settings/page.tsx:157-159`) and users (`ui/app/system/users/page.tsx`, `users-sections.tsx`). Shared clients are `ui/lib/api-config.ts`, `api-policy.ts`, `api-console.ts`, `api-request.ts`.
- Published docs reviewed against implementation: `docs/openapi.yaml`, `docs/mkdocs/api-reference.md:13`, `config-format.md:9,54-70`, `services.md`, `cli.md:80`, `logging-evidence.md:50,77`, `update-policy.md:24-52,67-74` and the root conventions/domain boundaries. Documentation describes backup/evidence preservation, manual signed-container updates and pinned classroom releases; these are appropriate product goals, not proof of complete restore or readiness.
- Tests span config/store/validation/strict JSON, HTTP auth/MFA/domain/backup/runtime/route inventory, service renderer/process/protocol helpers, templates/audit and CLI clients/formatting. Appendix A names the meaningful fixtures and limits; only three single tests were executed. No formal visual/accessibility rating is inferred from source review.

## 2. Maturity rating per capability

Ratings are relative to mature **training/containerized** operations, not physical-firewall certification. Unless explicitly marked Inferred, implementation descriptions are Verified.

| Capability | Rating | Evidence and boundary |
|---|---|---|
| Typed configuration and domain validation | **partial** | Broad model + consistency pipeline (`config.go:14-30`; `validate.go:19-71`); strict rules/ICS (`rule_json.go:17-35`, `ics_json.go`), but other objects permissive and service cross-field validation incomplete (F17). |
| Candidate / diff / commit | **partial** | Real promotion and previous snapshot; process-level apply serialization (`store.go:239-312`; `server.go:473-488,562-651`); no revision/ownership/CAS or durable apply acknowledgement. Known Save behavior is separately in progress. |
| Commit-confirmed / rollback | **partial** | Persisted timer and boot rearm (`store.go:319-451,549-568`), runtime replay notifier; not crash-atomic and no public pending state (F5). |
| Import/export and portable restore | **partial** | Real validation/redaction/import, local backups, separate IDS backup; config downloads are incomplete policy/instance recovery (F4). |
| Templates | **partial** | Real built-ins, mode override, preview/upsert (`templates.go:61-94`; template handlers); UI preview shape mismatch and no provenance/version (F10). |
| Administrative audit | **partial** | SQLite records and auth/MFA/commit events; missing critical CRUD events, best-effort writes, no integrity/retention/filter/export API (F7). |
| REST API / RBAC | **partial** | Every facade route classified above; explicit mutator gates, session revocation checked per HTTP request; no resource/action-scoped roles; incomplete contract and connection-lifetime auth (F8/F11). |
| CLI parity | **partial** | Extensive shared role-aware registry, API-backed writes; missing dedicated service/user/MFA/backup commands, warning loss, local-file semantics in remote console (F12). |
| DNS | **partial** | Unbound render/check/start/status/query stats; `listenZones` not enforced and resolver permits all IPv4 clients (F9). |
| DHCPv4 | **partial** | Engine runtime, config render, pools/reservations, lease API/audit ingest; render status is not engine readiness; weak range/reference validation (F17). No DHCPv6/failover is modeled. |
| NTP | **partial** | chrony/openntpd client render/validation/status; requires root + CAP_SYS_TIME to run (`ntp.go:310-332`). No synchronization proof/offset status, container-clock posture must be explicit. |
| Syslog | **partial** | Real UDP/TCP events, retry/counters; mixed ID suppression reproduced, request-bound lifetime, no durable spool/TLS/audit forwarding (F1/F2). |
| AV / ICAP / ClamAV | **partial** | Real HTTP-preview → worker → scanner → later flow-block wiring (`pkg/app/engine/av_support.go:24-139`), **not absent** despite stale comments; broken ClamAV terminator reproduced, ICAP transport/framing and fail-policy contract incomplete (F3/F6). |
| Forward / reverse proxies | **partial** | Envoy/Nginx render/validate/process/status; forward ACL/bind/upstream fields not enforced, no first-class auth/session access controls (F9). |
| TLS / outbound trust | **partial** | Real cert-pair validation and live cert reloader (`system_handlers.go:88-149`; `mgmt.go:294-307`); CA upload is stored but unused by outbound clients (F13). |
| Observability | **partial** | Prometheus, runtime service state, event rings, dashboard/health; enabled≠running gauges and synthetic UI activity, no durable desired/applied readiness/history (F14). Health always-200 is deliberate liveness, not a bug. |
| Upgrades / migrations | **partial** | Manual signed-image workflow (`docs/mkdocs/update-policy.md:24-52`), patch-version bump (`version.go:75-102`) and lazy embedded-IDS migration (`store.go:495-520`); no general transformation chain, guided preflight or demonstrated old-image/old-data recovery matrix. |
| Multi-instance isolation | **partial (deployment only)** | Separate env-selected DB/service paths and one configured engine URL permit isolated stacks; no instance-aware policy/session/audit namespace. Never share one SQLite volume among replicas. |
| Central management / HA | **absent** | No enrollment, fleet inventory/rollout/drift/replication contract in model/store/API/UI; recommend reproducible per-lab orchestration before a cluster. |
| Fine-grained SRA governance | **absent in this area** | Only admin/view roles and local users; no approver/operator/vendor scopes, expiring grants or policy review workflow (`auth.go:18-23`; `config.go:14-30`). Delegate detailed SRA roadmap to that area. |

## 3. Bugs and debt found (ranked)

Severity: **High** = broken protection/recovery/evidence or privileged-access promise in supported lab/container use; **Medium** = misleading state, data loss with a narrower trigger, or substantial operational gap; **Low** = limited/documentation-only friction. These are audit priorities, not CVSS scores. No exploit against a live deployment was attempted.

### F1 — High: syslog suppresses engine events after management events (Verified, reproduced)
`pkg/app/mgmt/mgmt.go:90-101` concatenates engine events followed by management events. Management IDs begin at `1<<63` (`pkg/cp/services/manager.go:78-80`), while `syslog.go:186-212` walks the concatenation backwards using **one monotonically increasing lastID**. It sends a management event, raises the watermark above all engine IDs, then skips engine events both in that batch and subsequent batches. The forwarder's own service events can trigger this. A UDP fake-collector probe received only management ID 9223372036854775809, never engine ID 1 (test exit 1). **Inferred impact:** missing firewall/IDS evidence despite increasing successful-forward counts. Fix with per-source/run cursors and explicit merge ordering; test mixed streams and engine restarts, not just one monotonic fake stream. Also advance destination cursors only on acknowledged delivery; current code advances after failed sends (`syslog.go:198-212`).

### F2 — High: a management write can stop syslog forwarding when its request ends (Verified code; runtime effect Inferred)
`SyslogManager.Apply` cancels/replaces the previous worker (`pkg/cp/services/syslog.go:68-98,134-160`) and derives the worker's lifetime from the supplied context. HTTP commit applies services with `c.Request.Context()` (`api/http/server.go:481,593-595`); direct service POST/PATCH similarly passes request context (`service_handlers.go:81-85,91-103`). Net/http cancels that context when the request finishes. Thus a normal config/service write replaces a daemon-lifetime forwarder with a short-lived one; no subsequent restart is guaranteed. Startup replay uses a daemon context, so this is specifically an update-path regression, not proof that syslog never starts. `Stop()` sends on a channel the forwarding select never observes (`syslog.go:154-159,333-339`). Separate request validation from manager-owned worker lifetime, cancel/join on shutdown, and test a real request ending before the next flush. No extra lifecycle test was run in this audit's three-test budget.

### F3 — High: ClamAV client rejects correctly NUL-terminated scan replies (Verified, reproduced)
Client sends `zINSTREAM\0` but reads a newline-terminated response (`pkg/cp/services/clamav.go:35-55`). With a protocol-correct `stream: Eicar-Test-Signature FOUND\0` reply and peer close, it returns `verdict="", error=EOF` instead of malware. Probe exit 1 reproduces this. The existing fake always appends newline (`av_helpers_test.go:59-106`), masking the mismatch. **Inferred impact:** default fail-open may bypass infected previews; fail-closed is also ineffective as described in F6. Correct terminator/response classification and test real clamd framing (including partial reads, malformed/truncated replies and clean/error results). This was a fake protocol peer, not a real ClamAV daemon test.

### F4 — High: downloaded backups/exports do not round-trip the whole policy (Verified; prior finding confirmed)
Local backup creation loads IDS separately and writes `<id>.ids.json` (`api/http/config_backup_handlers.go:256-305`) but download streams only `<id>.json` (`346-361`); export also serializes only `store.Load()` (`27-58`). Split rules are not injected (`pkg/cp/config/store.go:170-174,234-236`). IDS load/sidecar serialization/write/rename errors are ignored, metadata still advertises a count. No endpoint downloads/restores that sidecar. Import reads only Config (`config_backup_handlers.go:74-88`). **Inferred impact:** restoring a downloaded “full” backup to a fresh instance loses custom IDS rules; restoring on the original instance can retain unrelated current IDS rules. The UI does expose separate IDS backup/restore (`ui/lib/api-config.ts:42-54`), a workaround, not a complete bundle. Config backups also omit users/MFA/session policy, audit, TLS keys/certs, OpenVPN CA/client profiles/keys, authorized keys and custom AV definitions; paths alone are not recovery. Clearly distinguish redacted teaching exports, complete policy bundles and sensitive instance archives. Require clean-instance restore tests and error propagation.

### F5 — High: commit-confirmed persistence is not crash-atomic and confirmation can report false success (Verified; prior finding confirmed)
`Commit` and `CommitConfirmed` write previous/running/candidate/pending as separate statements (`pkg/cp/config/store.go:294-347`). Failure after promotion but before pending persistence leaves changed running state without the promised rollback timer. Candidate delete and pending-clear errors are discarded (`310-311,339,354,369`); `ConfirmCommit` always returns nil even if durable pending deletion fails. The mutex protects only this process, not a crash or another process. Startup rearm (`549-568`) is useful but cannot recover a pending row never written. Auto-rollback failure is logged once without rescheduling (`434-436`). Repeated commits overwrite the single `previous`, so a second confirmed commit can move the rollback anchor away from the last known confirmed state (`331-346`). **Inferred impact:** unsafe remote-change rollback and confirmation guarantees. Make each lifecycle transition one DB transaction with explicit pending policy and fault injection; expose ID/deadline/base revision. Preserve existing restart replay/notification tests.

### F6 — High: AV's security controls exceed its implemented enforcement contract (Verified)
- **Fail closed does not close traffic.** Scanner errors under `failPolicy=closed` return verdict `error` (`pkg/cp/services/av.go:341-369`); engine callback acts only on `malware` and returns for every other verdict (`pkg/app/engine/av_support.go:97-107`). Traffic is scanned asynchronously from HTTP previews, not held pending verdict (`pkg/dp/engine/runtime_events.go:139-165`; `pkg/dp/itdpi/http.go:49-52` caps previews at 4096 bytes). A later block is not an in-flight content guarantee. Queue overflow only emits a dropped-task event (`av.go:552-559`). UI explicitly offers “Fail closed” (`ui/app/system/services/av/page.tsx:314-323`).
- **ICAP TLS is a no-op.** Model/UI expose `useTls` (`config.go:850-853`; AV page:393-399), but both probe/scan use plain `net.Dialer` TCP (`pkg/cp/services/icap.go:38-40,79-81`), with no TLS branch. **Inferred impact:** preview content is sent in cleartext or fails against a TLS-only service despite selected TLS.
- **ICAP framing/interoperability is incomplete.** `res-body` offset includes payload length instead of just the encapsulated HTTP header; bytes are sent raw without ICAP chunk framing/terminator (`icap.go:93-101`). Any 2xx starts as “clean”; truncated header read silently breaks and returns clean (`107-124`); only one vendor-specific header is considered. No real ICAP interoperability proof exists in examined tests.
- Timeout/upload/download toggles are persisted but not used in scanner selection (search of `pkg/cp/services`, `pkg/app/engine`, `pkg/dp/engine` finds `TimeoutSec` only in status; no uses of `HTTPDownload`/`HTTPUpload`). Default values mutated after `m.lastCfg=cfg` do not become authoritative (`av.go:95-121`), including the purported forced ICS fail-open flag. Cache is not invalidated on policy/server/definition changes (`92-121,515-549`). Malware block errors are ignored while `service.av.block_flow` is emitted (`av_support.go:130-139`).
Recommendation: first publish and enforce an honest **asynchronous preview detector** contract; reject unsupported knobs, correct wire protocols, propagate block errors, then separately design whole-object/inline semantics if the product actually needs them. Do not advertise full file/malware prevention today.

### F7 — High: audit lacks essential privileged-change evidence and durable delivery guarantees (Verified; prior finding confirmed)
User create/update/password/delete handlers return success without audit (`api/http/users_handlers.go:39-150`); self password change similarly lacks a record (`auth_handlers.go:253-297`); TLS/trust upload (`system_handlers.go:88-196`), identity changes and both template applies (`template_identity_handlers.go:25-65,75-108,187-231`), syslog PATCH and AV-definition operations also omit explicit audit. Login failures and MFA actions **are** logged (`auth_handlers.go:59-80`; `auth_mfa.go`), so “no auth audit” would be false. `auditLog` discards Add errors (`server.go:765`); session actor is authenticated, but legacy/lab actor and all caller-supplied source can come from `X-User`/`X-Source` (`717-759`; `auth.go:73-111,258-267`). No universal denied-request audit middleware exists. SQLite has no cryptographic chain, retention/purge policy or filtered/export query interface (`pkg/cp/audit/store.go:69-128`); syslog's event lister does not read audit records (`mgmt.go:90-101`). **Inferred impact:** account takeover/role changes may leave no trustworthy off-box management evidence. Define mandatory audited actions/outcomes/actor/IP/request ID/revision, sanitize commands/secrets, use a reliable audit sink and bounded retention. Factory reset intentionally wipes local audit (`factory_reset.go:96-104`); preserve evidence externally before classroom reset, as docs already advise.

### F8 — High: SSH does not enforce web account MFA/remediation policy; long-lived console authorization is incomplete (Verified; coordinate SRA owner)
SSH password/public-key callbacks check account role plus password/key, but never MFA enrollment/requirement or MustChangePassword (`pkg/mp/sshserver/server_auth.go:58-112`). PTY users can reach a native shell even in appliance mode (`server.go:329-334`; `server_pty.go:57-71`); shell launches as the service process without per-user OS credential switching in that path. HTTP restrictions cannot constrain that shell. **Inferred impact:** an admin protected by web MFA can still obtain shell access with one SSH factor when SSH is reachable/configured; forced password remediation does not prevent that route. Password brute-force limiter includes remote **source port**, so reconnects change its key (`server_auth.go:63`). Treat SSH as a distinct break-glass capability with explicit policy, MFA/device identity and audit, not an equivalent web login.
WebSocket CLI authenticates once then loops without read limit/deadline or user/session recheck (`api/http/cli_handlers.go:130-163`); command context snapshots role. API-backed mutations do go through HTTP auth again, so this is **not** a proven post-revocation arbitrary-config-write bypass. Local diagnostics/file commands and connection resource usage remain open until disconnect. SSH also snapshots admin context while API requests revalidate (`server.go:169-202`). Add lifetime/revocation checks and disconnect behavior for both console transports; do not mistake UI `isAdmin()` for enforcement.

### F9 — High: DNS and forward-proxy scope controls are not enforced (Verified)
DNS `listenZones` is modeled as future binding (`pkg/cp/config/config.go:149-155`) and accepted by validation, but generated Unbound always listens on `0.0.0.0` and allows `0.0.0.0/0` (`pkg/cp/services/dns.go:159-160`). Forward proxy similarly listens on all IPv4 addresses (`proxy.go:669-676`); `listenZones`/`upstream` become comments (`702-706`), and `AllowedClients` is not rendered (`config.go:175-178`; `proxy.go:199-213`). Allowed domains do render and are not the missing control. **Inferred impact:** users selecting zones/clients may expose an open resolver or unauthenticated proxy to reachable container networks. This does not establish Internet exposure; actual reachability depends on Docker/network/input policy. Enforce supported binds/client ACLs or reject unsupported restrictions instead of accepting security-shaped no-ops. Upstream URL credentials also survive general config redaction and view-readable service GETs (`config.go:55-66`; `service_handlers.go:415-426`). Avoid storing credentials in an unredacted string.

### F10 — High (training workflow): successful ICS template preview can crash rendering (Verified static producer/consumer mismatch)
API preview returns `[]config.Rule` (`api/http/template_identity_handlers.go:198-208`), whose protocol/function codes are nested at `ics.protocol` / `ics.functionCode` (`pkg/cp/config/config.go:782-807`). UI asserts a different flat `TemplateGeneratedRule` shape (`ui/app/templates/page.tsx:27-36`) then calls `protoBadgeClass(r.protocol)` → `proto.toLowerCase()` (`112-114,455-463`). The actual `r.protocol` is undefined. **Inferred runtime symptom:** TypeError instead of a preview; wildcard function-code display would also be false. No browser was opened. Use shared canonical rule DTO/normalizer and a rendering contract test. Other template gaps: UI request has no `mode` despite API/CLI learn/enforce support (`38-43,256-262`), preview button is shown to viewers but POST is admin-only (`405-412`; router:376), raw fetch bypasses common token-refresh/error handling (`53-97`), and modal lacks dialog semantics/focus trapping/escape handling (`307-321`). These are separate from in-progress rule-save/commit UX. General template vs ICS collision behavior also differs (skip vs overwrite); expose previewed updates and provenance rather than silently surprising learners.

### F11 — Medium: OpenAPI is not a reliable automation contract (Verified census)
101 of 164 facade-registered versioned operations are undocumented (full list above). Entire families missing include backup/export/validate/confirmed/confirm/diff, CLI, zones/interfaces/assets/objects/routing/NAT, IDS import/export, AV/proxies/service status, TLS/system, VPN profile/client operations. `/api/v1/engine/config` GET/POST is documented but unregistered (`docs/openapi.yaml:1320-1344`); actual config route is `/dataplane` (`server.go:282-286`). `docs/mkdocs/api-reference.md:13` nevertheless claims zones/interfaces/assets/diagnostics coverage. Most config/service bodies are untyped `object` schemas (`openapi.yaml:688-736,903-965`), roles mostly appear only in prose, error/nullable/status/warning contracts are inconsistent. `/audit` is conditionally registered outside the facade and is **not** a phantom endpoint. Add a route↔spec CI census including optional routes plus schema/role/negative-response contract tests. The stated 10-MiB import limit (`openapi.yaml:789`; backup handler:64) is preempted by the group's 8-MiB JSON limit (`util.go:27-29,114-140`); document/enforce one limit.

### F12 — Medium: CLI is broad but not API-equivalent and hides apply warnings (Verified)
Registry has no dedicated DNS/NTP/DHCP/VPN/AV setters, users/MFA management, backup CRUD, config-validate or candidate-file load commands (`pkg/cli/registry.go:44-145`). Whole-config import/interactive setup can cover some needs, but this is not first-class parity. `analyze pcap` is registered `RoleView` (`83`) while target POST requires admin (`server.go:298`): view users reach a guaranteed authorization error. `show learn rules` similarly calls admin-gated `/learn/generate` (`registry.go:95`; router:342). `postJSON`/`patchJSON` discard `X-Containd-Warnings` and print only `ok` (`pkg/cli/api_client.go:63-92,141-170`), unlike UI mutation clients. **Inferred impact:** SSH automation reports success while routing/enforcement is degraded (F14). File-based commands open paths on the management host when invoked through the in-app CLI (`cli.go:111-115,436-449`; `pcap_analyze.go:14-25`), not on the browser user's workstation; diagnostics are also in the mgmt namespace, not necessarily engine namespace. Clearly separate local-client vs remote-console commands, expose warning/structured status, generate discoverable command/API role tables, and add parity assertions.

### F13 — Medium: uploaded “trusted CA for outbound TLS” is unused (Verified bounded code search)
Model/UI promise extra outbound trust (`pkg/cp/config/config.go:94-96`; `ui/app/system/settings/page.tsx:157-159`). Handler accepts any PEM block and writes it (`api/http/system_handlers.go:156-213`), not necessarily X.509 CA material. Repository Go search for `TrustedCAFile`, `trusted_ca`, `AppendCertsFromPEM` finds model, validator, upload handler and CLI display only—no outbound TLS transport loads the bundle. **Inferred impact:** operator follows the UI but custom-CA peers remain untrusted; this does not prove TLS validation is bypassed globally. Validate CA certificates and wire an explicit reloadable trust provider to actual consumers, or remove the unsupported promise. TLS cert/key upload itself validates the pair and reloads new connections; pair writes are non-atomic (`system_handlers.go:138-148`), an adjacent recovery improvement.

### F14 — Medium/High: desired state, readiness and evidence are conflated (Verified; prior apply finding confirmed)
Commit persists first, then applies managers/engine (`api/http/server.go:477-488`). Manager errors can return 500 **after** persistence and partial service changes (`593-595`; `pkg/cp/services/manager.go:282-315`). Engine infrastructure failures and selected ApplyRules errors become warning headers and HTTP 200 (`server.go:600-662`). This is deliberate permissive-lab behavior, but there is no durable per-subsystem desired/applied revision/last-error API. Engine boot replay sets `applied=true` even when warnings exist (`pkg/app/mgmt/engine_sync.go:115-125`) and suppresses retries for unchanged boot ID (`112-114`); **Inferred:** transient warning-only apply failures can remain indefinitely without new commit/restart. A successful save/commit is not proof of protection.
Metrics named `ServicesRunning` are set from configured `Enabled` flags even if Apply failed (`pkg/cp/services/manager.go:308-332`); CLI marks DNS/NTP running from enabled state despite actual running fields (`pkg/cli/services.go:157-183`). DHCP manager explicitly reports only config render (`dhcp.go:107-118`), not engine readiness. AV management instance reports local state while scan work runs in engine (F19). DNS/NTP pages derive fixed synthetic sparklines (`dns/page.tsx:64-67`, `ntp/page.tsx:59-62`); NTP labels its title simulated (`163-168`), but this is not real synchronization evidence. Service overview manufactures fallback trends (`system/services/page.tsx:23-30`). General events remain process-memory stores (`manager.go:78-80`); durable audit is different. Keep always-200 liveness (explicit contract), add separate authenticated readiness/applied-status, label unknown/stale/simulated and separate enabled/running/healthy counters.

### F15 — Medium: redacted candidate round-trip can revert newly staged secrets (Verified; prior finding confirmed)
Candidate GET strips VPN private keys/passwords (`api/http/server.go:448`; `pkg/cp/config/config.go:55-64`). Candidate POST restores empties from **running**, not the existing candidate (`server.go:459-463`). Stage a new key, reload the redacted candidate, edit an unrelated field and save: old running key is substituted. **Inferred impact:** credential rotation appears staged but is silently undone. Use explicit secret patch semantics tied to candidate revision, distinguish preserve/delete/replace, and test a two-edit staged rotation. Import of redacted exports also does not call RestoreRedactedSecrets (`config_backup_handlers.go:74-88`); empty secret fields can erase existing keys or make validation fail. Clearly mark redacted exports non-restorable without a secret source. Do not fix by copying arbitrary stale running data over candidates.

### F16 — Medium: globally shared candidates and read-modify-write handlers lose concurrent administrator work (Verified structure; conflict outcome Inferred)
Store API has no revision/base/owner/lock/CAS (`pkg/cp/config/store.go:31-47`), candidate write is a standalone replace outside the commit mutex (`200-220`); handlers accept whole configs without `If-Match` (`server.go:452-469`). Diff has only two snapshots, not change identity (`665-680`). Two browser tabs/CLI operators can overwrite each other's edits or confirm someone else's pending commit. Multi-process operation has independent in-memory mutexes and rollback timers. This is separate maturity debt from the **in-progress Store.Save issue**, not a re-report of it. Add immutable revisions, optimistic concurrency, actor-owned change sets and explicit publish/confirm IDs before multi-user/fleet governance.

### F17 — Medium: service validation and published config schema admit silent mistakes (Verified)
DHCP pool validation parses start/end IPv4 but does not compare order, subnet membership, overlaps or reference actual configured interfaces (`pkg/cp/config/validate_services.go:145-200`; only VPN gets interface/zone sets at:28). Reservations detect duplicate MAC/interface but not duplicate assigned IPs. DNS/NTP/proxy mostly enforce non-empty strings/ranges, not full supported grammar; generated daemon configs interpolate values. Full candidate validation does not invoke manager-level daemon validation (`api/http/server.go:422-433,452-465`; `config.Validate`); DNS direct setter does (`service_handlers.go:166-173`). Daemon validation/render can therefore fail only after durable commit, with earlier services already changed. NTP/proxy render overwrites live config paths **before** syntax validation (`ntp.go:149-157`; `proxy.go:158-168`). DNS checks for binary presence before disabled branch (`dns.go:123-128`), so even a disabled missing optional DNS binary can block commit service apply before rules (`server.go:593-595`). Reject unsupported config early, render/validate into temporary artifacts and activate atomically.
Docs use `routing.staticRoutes`, `policyRules`, `via`, `dev` (`docs/mkdocs/config-format.md:54-70`); actual fields are `routes`, `rules`, `gateway`, `iface` (`config.go:644-675`). Non-rule config objects use normal JSON unmarshalling, so those routing keys are discarded rather than rejected. DHCP UI/docs expose `authoritative`, absent from Go DHCPConfig (`ui/app/dhcp/page.tsx:17-27`; `config.go:200-209`). Config sample is illustrative and also references an undefined OT zone, so copying it whole may fail validation; do not treat it as a golden fixture. Make published examples executable valid fixtures and extend strict/duplicate/unknown-key handling beyond firewall/ICS. Preserve the existing strictness guarantees.

### F18 — Medium: factory reset is a persisted-state reset, not a runtime reset (Verified)
Handler has no engine/services dependency (`api/http/factory_reset.go:20`); wipes/reseeds users/config and audit but never applies defaults, stops services, clears engine rules or reloads listeners (`38-113`). Engine sync polls by engine boot ID and suppresses repeated replay after success (`engine_sync.go:112-125`), so a DB reset alone does not force convergence. **Inferred impact:** UI/default login suggests a fresh appliance while old firewall/VPN/service runtime continues until another apply/restart; custom files/backups are also outside this reset. Do not execute reset in audit. Define the classroom reset contract, explicitly preserve/delete sensitive state, apply defaults with completion/readiness acknowledgement, then verify from both planes. Coordinate with known Save work without reopening it.

### F19 — High/Medium: saving AV config updates the wrong runtime instance until a later full apply (Verified)
`setAVHandler` accepts no engine client and calls `applyServiceRuntime(..., services, nil)` (`api/http/service_handlers.go:232-261`); management manager's AV instance is separate from the engine scanner (`pkg/app/mgmt/mgmt.go:80-103`; `pkg/app/engine/engine.go:102-105`, `av_support.go:19-46`). Engine AV receives settings via `/internal/services` only (`pkg/app/engine/runtime_handlers.go:155-159`) during commit/engine replay or engine-aware service operations. **Inferred impact:** UI reports AV saved/enabled while traffic scanner retains old/disabled settings; local management status/probe is not authoritative. The AV page shows saved success (`ui/app/system/services/av/page.tsx:79-101`) without requiring commit. Forward engine-owned AV configuration immediately or make it explicitly staged with applied revision/readiness; use one authority for status and definition-update outcomes. Management freshclam is launched with request context in manual update (`av.go:478-496`), so command execution can also be canceled when HTTP 202 returns (verify in an integration test).

### F20 — Medium: service forms turn fetch errors into defaults and can discard unsaved settings (Verified)
Shared `getJSON` returns null on non-OK/network errors (`ui/lib/api-request.ts:10-30`), so form-level try/catch often never fires. DNS/NTP refresh replace config with disabled/default values and mark updated time (`dns/page.tsx:32-45`; `ntp/page.tsx:29-40`); DHCP normalizes null and emits success (`dhcp/page.tsx:78-94`). Auto-refresh reuses those setters during editing. **Inferred impact:** failure or periodic poll erases a draft and a subsequent Save can persist unintended defaults. Preserve last good values/draft dirty state, distinguish loading/error/stale/empty, and cancel requests. Syslog add/delete explicitly reconstruct only `{forwarders}` (`ui/app/system/services/syslog/page.tsx:80-90`), dropping selected format/batch/flush settings on editing; use a full-state update. Audit pagination only browses the newest default 100 fetched rows, even though API supports offset (`ui/app/audit/page.tsx:15-34,99`; `ui/lib/api-policy.ts:100`; `api/http/audit.go:17-44`). Bind server-side paging/filtering before calling it a full log search.

### F21 — Medium: management event IDs exceed JavaScript's integer precision (Verified interface mismatch; UI symptom Inferred)
Management IDs start above 2^63 (`pkg/cp/services/manager.go:78-80`) and serialize as JSON numeric `uint64` (`pkg/dp/events/store.go:22-23` Event model). UI uses numeric IDs and passes `number` into getEvent (`ui/lib/api-console.ts:21`), but JavaScript cannot uniquely represent these consecutive values above 2^53. **Inferred impact:** duplicate React keys/rounded event IDs/detail 404s for service events and loss of evidence identity. Use opaque string event IDs end-to-end; keep source/run identity for F1 as well. No browser test was run; check all consumers before changing the wire contract.

### Additional bounded debt and open questions
- **IDS lifecycle boundary (Verified / consequence Inferred):** candidates may contain embedded IDS rules (`store.go:200-216,307-308`), but running apply injects the separately stored table over them (`server.go:631-637`); an existing nonempty table wins (`store.go:497-504`). Config previous/rollback does not snapshot that table. Decide whether candidate/confirmed/rollback covers IDS rules; currently “whole config” is not equivalent to whole enforcement policy. Validate custom-IDS rollback and fresh restore alongside F4/F5, without re-auditing known Save semantics.
- **Low, stale docs:** `pkg/cli/README.md:5`, `pkg/cp/services/manager.go:28-29`, `av.go:195,272-273` understate implemented process/scanning behavior. `docs/mkdocs/cli.md:80` says lab mode disables auth checks although lab middleware requires a token and validates JWT when configured (`auth.go:73-90`). Describe intentionally insecure lab posture precisely; do not silently change workshop defaults.
- **Open:** no live test proves all Envoy/Nginx builds, external ICAP vendors, DNS trust, NTP clock status, custom definition reload or rollback recovery under process/storage failures. Renderer/fake tests do not establish those properties. No production appliance claim is required to fix deceptive security controls or dropped training evidence.
- **Open:** whether students need shared-instance least privilege or one isolated container stack each. Prefer isolated per-student instances with scoped admin until governance requirements justify resource-scoped control. No uncontrolled HA/fleet expansion is recommended ahead of secure remote access.

## 4. Ranked gaps against a mature training/containerized firewall

These are **Inferred product gaps** derived from the Verified findings, not claims that the absent features were promised. Ranking emphasizes the next secure-remote-access lab and reliable classroom recovery; fleet scale does not outrank trustworthy single-instance operation.

| Rank | Required outcome | Present gap / evidence | Why it matters in the stated product frame |
|---|---|---|---|
| 1 | One coherent management-access boundary across HTTP, SSH, console and native shell | Admin/view only; SSH ignores web MFA/remediation; long-lived transport revocation incomplete (F8; `server_auth.go:58-112`, `cli_handlers.go:130-163`). | SRA lab must not teach that web MFA protects an unrestricted alternate shell. Decide break-glass scope with the SRA owner before adding roles or broker features here. |
| 2 | Reliable, attributable off-box administrative and engine evidence | Mixed-source syslog drop reproduced, request-lifetime worker, incomplete account/privileged audit, volatile event buffers and rounded UI IDs (F1/F2/F7/F21). | Students/instructors must be able to correlate access, change and traffic outcomes; a successful-forward counter is not an evidence chain. |
| 3 | Crash-safe changes and repeatable recovery to the complete previous policy | Nontransactional commit-confirmed, shared unversioned candidate, split IDS lifecycle, incomplete downloaded backup, redacted-secret ambiguity (F4/F5/F15/F16). | A remote access policy mistake and an ordinary lab reset must be safely recoverable, including IDS and secrets. This work complements, not duplicates, the known Store.Save correction. |
| 4 | Honest protection and service-scope controls | ClamAV framing failure, asynchronous AV misrepresented as fail-closed, ICAP TLS ignored, AV saved in wrong process, DNS/proxy ACL-shaped no-ops (F3/F6/F9/F19). | Unsupported controls are worse than an explicit limited detector. Container reachability still matters even without physical-interface production claims. |
| 5 | Observable convergence, rather than success-shaped persistence | Partial apply after durable commit; warnings without persistent status/retry; enabled gauges masquerade as running; reset does not reset runtime (F14/F18). | Instructors need deterministic evidence that the exercise policy reached the engine and required services are healthy, not merely a green Save. |
| 6 | One discoverable, tested machine contract across API, CLI, UI and docs | 101 missing facade operations in OpenAPI; role/warning mismatches; broken template preview DTO; fetch errors become defaults (F10/F11/F12/F17/F20). | Automation and repeated lab setup must not depend on reverse-engineering UI fetches or silently dropping fields. |
| 7 | Safe service configuration lifecycle and usable operational status | Incomplete cross-field validation; render-before-check; missing binary blocks disabled DNS; DHCP render-only status; no NTP sync proof (F14/F17). | Container capabilities/namespace boundaries are explicit constraints; partial capability must be reported, not inferred from enabled flags. |
| 8 | Versioned, reproducible lab scenarios, upgrades and reset semantics | Version-bump-only generic migration, independent IDS migration, illustrative invalid config docs, incomplete archive/reset contract (`version.go:75-102`, `store.go:495-520`, F4/F17/F18). | Pin both images and scenario/schema versions; prove restore and rollback before an instructor upgrades a classroom. No ISO or unattended firmware updater is needed. |
| 9 | Multi-instance orchestration before central policy distribution | One engine URL, local SQLite, global candidate and local files; no instance/revision enrollment, targeting or drift API (inventory, F16). | Per-student isolated stacks are the smallest mature model. Fleet inventory and staged rollout can follow; shared-volume replicas or HA would magnify present consistency gaps. |

**Avoid scope inflation:** directory federation, approvals, time-bound grants, vendor access and session recording are SRA design work owned by the parallel audit. Control-plane prerequisites here are access invariants, mandatory audit, versioned change identity and readiness. IPv6 DHCP, rich analytics, HA and whole-file inline malware prevention are optional future requirements, not prerequisites for useful, well-bounded container labs. No current "solid" rating is justified for an entire capability family; individual pieces (typed firewall/ICS decoding, session-backed HTTP checks, persisted rollback rearm, service render/process supervision) are substantial and should be preserved.

## 5. Recommended staged roadmap

Sizes describe **estimated implementation footprint**, not time; generated schemas/types are additional. These are proposals, not implemented fixes. Each item needs explicit owned paths and a write lane; this audit owns no implementation. Scope one coherent change at a time and keep independent maintenance/doc fixes separate.

### Now — make the next lab safe, recoverable and truthful

**N1. Unify management access invariants; explicitly constrain break-glass SSH.**
- Outcome: decide whether native shell is disabled, a distinct strongly authenticated capability, or an explicitly documented lab-only escape hatch; apply MFA/remediation policy and session/account revocation to supported transports. Normalize limiter identity without source-port bypass; bound WebSocket message size, idle lifetime and total lifetime. Preserve HTTP per-request revalidation.
- Size: ~5–9 files; SSH authentication/session/PTY, HTTP CLI transport, identity/session policy and tests (3 subsystems). Addresses F8.
- Dependencies: **SRA owner/product decision first** on SSH MFA/device identity and break-glass policy; do not independently invent approver/vendor roles. Management bootstrap/recovery must remain possible through an explicitly audited path.
- Validation owner: SRA/identity owner plus management API owner. Add cross-transport tests for required MFA, forced password change, disabled/downgraded user, revoked/expired session, reconnect throttling and shell policy; use headless protocol peers. Whole touched lifecycle packages under race belong to the implementation/integration owner, not this audit.

**N2. Repair evidence delivery and management audit coverage.**
- Outcome: daemon-owned syslog worker with cancel/join; stable source/run IDs and per-destination delivery cursors; management audit included explicitly in off-box stream; record required user/role/credential/trust/template/reset changes and denied privileged actions. Emit delivery/storage health and bound queues/retention. Start with correctness; add durable spool/TLS as a separately reviewed increment, not a silent best-effort fallback.
- Size: ~7–12 files initially; mgmt event aggregation, syslog/services, HTTP audit helpers/handlers, event wire DTO and UI IDs (4 subsystems). Addresses F1/F2/F7/F21.
- Dependencies: stable event identity contract coordinated with dataplane exporter owner; SRA audit action taxonomy from N1. Audit failures need an explicit allow/deny/degraded policy; do not simply turn all lab writes into unexplained failures.
- Validation owner: services + audit owner. Promote retained mixed-stream probe into regression coverage; add engine restart/ID reset, management-only/engine-only, request cancellation, destination failure/retry, shutdown and audit-write fault tests. Verify real collector framing/TLS externally when that increment is introduced. Run the whole touched service lifecycle package under race after implementation.

**N3. Make candidate/confirmed/rollback transitions transactional and revisioned.**
- Outcome: one database transaction per state transition with immutable revision/change ID, base-revision CAS, actor, pending deadline and durable rollback anchor; reject or explicitly reconcile overlapping pending changes. Return pending state and actual apply outcome. Preserve staged secrets through explicit preserve/delete/replace semantics. Decide and implement one policy snapshot boundary that includes the split IDS store.
- Size: ~8–14 files; config store/model, HTTP lifecycle/IDS handlers, CLI/config UI, management replay and tests (4–5 subsystems). Addresses F5/F15/F16 plus IDS boundary debt.
- Dependencies: coordinate integration with **known Store.Save correction**, without taking over/re-reporting that work; freeze snapshot/IDS authority and pending-commit semantics before backup format N4 and convergence X1. SRA connectivity safeguards are a separate in-progress dependency, not solved by DB atomicity alone.
- Validation owner: config/store owner. Fault-inject each write/commit/delete, reopen after crash points, exercise repeated confirmed commits, expiry races, confirm/rollback failure, two concurrent writers and two-edit secret rotation. Preserve restart-rearm and notification tests. Add API tests asserting change ID/deadline/revision and CLI/UI pending-state rendering.

**N4. Deliver a complete, versioned policy bundle with explicit secret handling.**
- Outcome: manifest covering config + custom IDS and version/checksums; one validated snapshot; deterministic export/import; propagate all errors; validate before mutation; restore atomically into a fresh instance. Name redacted exports distinctly. Define a separate sensitive instance archive for required keys/users/custom definitions, with permissions, encryption/transport policy and a deliberate exclusion list for sessions/audit. Do not casually export reusable sessions or silently call config JSON a full backup.
- Size: ~6–10 files for policy bundle first; backup/import handlers, store snapshot API, UI/CLI adapters, documentation and round-trip tests (3 subsystems). Instance archive is a second ~5–9-file increment touching identity/file assets.
- Dependencies: N3 policy snapshot boundary; product decision on portable secrets versus instance identity and audit preservation. No hidden filesystem paths or unchecked tar extraction. Do not widen a read-only lane to implement this.
- Validation owner: config recovery owner. Restore to a clean store with nondefault IDS/VPN/secret references; compare normalized policy, reject unsupported schema/checksum/path traversal, inject sidecar/disk failure, exercise redacted-mode behavior and prove existing instance remains unchanged on invalid input. Image-level restore/rollback belongs to orchestrator-owned isolated stacks, not this audit.

**N5. Remove security-shaped no-ops and repair scanner/config routing correctness.**
- Outcome: fix ClamAV NUL framing and ICAP encapsulation/chunk/error/TLS handling; route engine-owned AV config/status to the engine; stop advertising fail-closed/full-file prevention for asynchronous previews. Reject unsupported timeout/upload/download/zone/client/upstream settings until implemented; correctly apply supported DNS/proxy ACLs and redact credential-bearing URLs. Either wire outbound custom trust to named clients with reload or remove its UI promise. Invalidate cache on relevant policy/definitions changes and surface block failures.
- Size: ~10–16 files over small separate commits; scanner clients, service renderer/manager, engine AV adapter, HTTP service/trust handlers, related UI and tests (4 subsystems). Addresses F3/F6/F9/F13/F19.
- Dependencies: AV/dataplane owner agrees on **preview detector** contract; SRA owner coordinates trust semantics; X1 later provides authoritative applied status. Implementing true whole-object inline AV is explicitly **not** the shortcut fix.
- Validation owner: services/scanner + engine adapter owners. Promote retained NUL-response probe; add fragmented/truncated/error replies, real clamd and representative ICAP interoperability, TLS peer validation, renderer ACL assertions, engine settings update assertions, queue saturation/block failure and stale-cache tests. Daemon/network integration deferred to isolated external/orchestrator runs.

**N6. Restore the core classroom UI/CLI contract without redesigning it.**
- Outcome: canonical template DTO, correct nested ICS display/mode, role-appropriate preview, accessible dialog behavior; preserve dirty service drafts and last good config on fetch failure; keep syslog fields during forwarder edits; CLI prints structured warnings and aligns command roles. Repair executable config examples and label simulated/unknown telemetry.
- Size: ~7–12 files; templates/services/config UI, shared API clients, CLI metadata/client, docs and focused tests (3 subsystems). Addresses F10/F12/F17/F20; coordinates F14 display semantics.
- Dependencies: API DTO decision from existing Go model; no dependency on a new visual design system. **Do not duplicate in-progress rule-save/commit UX or base-path icon fixes.**
- Validation owner: UI/CLI owner. Contract test consumes actual template JSON, tests viewer/admin affordances, failed/pending fetch with dirty forms, syslog full-state update, warning preservation and local-vs-remote file semantics. Headless accessibility/keyboard tests and route/browser smoke must be scheduled by orchestrator; no GUI opened here.

### Next — deterministic operations and an automation contract

**X1. Add durable desired/applied revision, retryable reconciliation and honest readiness.**
- Outcome: persist per-subsystem attempt/applied revision/error/time; replay retryable failures without a new engine boot; idempotent application; separate enabled/running/healthy/stale and liveness/readiness. Surface warnings as structured API data, CLI status and UI state. Factory reset becomes an acknowledged desired-state transition that converges runtime, with explicit file/evidence policy.
- Size: ~10–16 files; config lifecycle, mgmt engine sync, engine API, services runtime, metrics, UI/CLI and tests (5 subsystems). Addresses F14/F18/F19.
- Dependencies: N3 revision identity; N5 authoritative service ownership; known management-path preservation work. Decide permissive-training versus required-enforcement policy explicitly, with no blanket change to liveness semantics.
- Validation owner: CP/engine integration owner. Transient/permanent apply failures, engine restarts, duplicate/out-of-order attempts, partial services, reset, warning recovery and readiness assertions. Full touched lifecycle race suites and Linux/container smoke belong to orchestrator after merging.

**X2. Make OpenAPI, role matrix and clients executable contracts.**
- Outcome: cover every actual route including conditional audit; remove phantom engine/config paths; typed body/result/error/warning/revision schemas; explicit authorization metadata; one body-size limit. Generate shared UI/client types where practical and a CLI support matrix; retain handwritten domain validation. Add complete admin/view/anonymous/expired/remediation endpoint tests rather than status-only sanity.
- Size: ~8–14 authored files plus generated schemas/types; router metadata, OpenAPI, API tests, UI API adapters, CLI registry and doc generation (4 subsystems). Addresses F11/F12/F17/F21.
- Dependencies: N3 revisions, N5 service contracts and X1 state vocabulary; can first land a no-semantic-change census/test inventory. Confirm preview authorization intentionally rather than broadening all POST permissions.
- Validation owner: API contract owner with UI/CLI consumers. Registration/spec bidirectional diff, schema examples and generated-client checks; positive/negative role matrix for all optional route sets, secret-field/read-mode tests, warning and nullable/error behavior. Existing route inventory is a useful base, not a sufficient oracle.

**X3. Treat service configuration as validated, staged artifacts.**
- Outcome: validate references/range order/overlap/duplicate IPs and supported daemon grammar before persistence; render/check temp artifacts, atomically activate/revert; disabled optional daemons must not fail merely because binaries are absent. Report DHCP engine leases/readiness and NTP synchronization/capability constraints truthfully; define external versus in-container NTP posture.
- Size: ~8–13 files; config validators, DNS/NTP/DHCP/proxy managers, service API/status UI and tests (3–4 subsystems). Addresses F9/F14/F17.
- Dependencies: N5 explicit supported knobs; X1 reconciliation semantics. DHCP/clock/kernel capability tests require isolated authorized containers; do not grant broad host privileges to make status green.
- Validation owner: service lifecycle owner. Golden daemon render/check fixtures, disabled-missing-binary, invalid config leaves active files/process unchanged, ranges/references/overlap and real lease/time-status checks. Whole touched lifecycle packages under race plus platform-specific integration after merge.

**X4. Publish reproducible scenario/reset/upgrade compatibility.**
- Outcome: version scenario/template provenance; pin mgmt+engine image digests and config schema; enforce preflight compatibility; publish classroom restore/reset checklist and tested upgrade/downgrade data handling. Preserve off-box audit before reset and define retained backups/keys. Extend patch-version bump/lazy IDS migration only when actual schema transformations require it; reject unknown paths rather than silently guessing.
- Size: ~6–11 files; config migration/version fixtures, bundle manifest, templates metadata, deployment/docs scripts and compatibility tests (4 subsystems). Addresses F4/F5/F10/F17/F18 and upgrade maturity gap.
- Dependencies: N3/N4 snapshots, X1 runtime reset/readiness and SRA enrollment/identity recovery semantics. Keep containd release/schema versions independent; next release is **0.1.33**, not RangerDanger's version.
- Validation owner: recovery/release integration owner. Supported-old-schema fixtures → current → restored policy, bad/future-version rejection using a guaranteed-different derived version, clean-instance archive restore, previous-image plus matching data rollback, template idempotence/provenance and deterministic lab reset. No ISO work or unattended updater required.

### Later — scale a reliable single instance, only when justified

**L1. Fleet inventory and lab orchestration before central policy/HA.**
- Outcome: isolated per-student instance identity, enrollment, image/scenario/revision inventory, targeted signed/scoped operations, drift and staged rollout; central actions delegate to versioned per-instance changes with per-instance audit. Do not share SQLite/data volumes or infer cluster safety from HTTP statelessness.
- Size: new orchestration subsystem (~10–20 authored files initial inventory/targeting) plus ~5–9 management API/identity/deployment files; central policy distribution is a separate increment. Dependencies: N1/N2/N3/N4 and X1/X2; SRA/fleet threat model and explicit multi-tenant product requirement. Validation owner: fleet + SRA integration owners; wrong-instance targeting, credential isolation, offline/retry/drift, partial rollouts and rollback.

**L2. Resource-scoped administration and richer access governance.**
- Outcome: action/resource scopes, delegated operator/instructor/vendor grants and policy approvals integrated with SRA; API keys/service identities distinct from users; immutable change review/audit. This is not a new role string sprinkled through handlers.
- Size: ~12–20 files across identity, shared authorization middleware, API/CLI/UI, tests (4 subsystems), after a separate authorization model design. Dependencies: SRA roadmap, N1/N2 and X2 complete endpoint inventory; per-student isolation may eliminate immediate need. Validation owner: SRA/security owner; deny-by-default cross-resource/cross-instance matrix and connection revocation.

**L3. Optional deeper protection/availability features, behind explicit product decisions.**
- True whole-object inline malware handling, encrypted-content inspection, DHCPv6/failover, HA control plane and rich historical analytics need independent requirements/threat models and prototypes. Size: **new subsystems**, not small extensions to current renderers/preview scanner; file footprint must be scoped after design. Dependencies: measured demand from container workloads and N/X reliability baseline. Validation owner: relevant dataplane/services/operations owners. No physical-interface appliance or ISO milestone is proposed.

**Suggested dependency order:** N1/N2 and small N5/N6 correctness fixes can proceed independently; N3 defines N4/X1; X1+X2 stabilize automation; X3/X4 make repeatable labs; only then consider L1/L2. Do not block the next useful lab on fleet/HA or whole-file AV. Do block claims of protected remote administration, reliable audit, complete backup or fail-closed scanning on the corresponding demonstrated invariants.

## Appendix A — Validation, evidence limits and retained probes

### Executed tests (three single tests total)

Commands ran from `<containd-checkout>`, with no Docker or source modifications. Failed tests are **observed defect reproductions**, not ignored validation failures or passing gates. External probe file is retained at `<audit-artifacts>/control_plane_probe_test.go`.

1. `GOFLAGS=-mod=mod go test <audit-artifacts>/control_plane_probe_test.go -run '^TestClamAVNULTerminator$' -count=1 -v`
   - **Exit 1; one test executed, failed.** Fake Unix clamd peer consumed zINSTREAM frames and returned a NUL-terminated FOUND reply. Observed `verdict="" error=EOF`, expected malware without error (F3). It proves client parsing, not a live deployment exploit or real-daemon compatibility. Probe does not delete its temporary Unix-socket path.
2. `GOFLAGS=-mod=mod go test <audit-artifacts>/control_plane_probe_test.go -run '^TestSyslogMixedEventIDs$' -count=1 -v`
   - **Exit 1; one test executed, failed.** Ephemeral loopback UDP collector received management ID `9223372036854775809`, but no engine ID `1` from a lister shaped like the real aggregator (F1). It proves the mixed-ID cursor defect, not delivery to a production collector.
3. `GOFLAGS=-mod=mod go test ./api/http -run '^TestViewerCannotAccessAdminEndpoints$' -count=1 -v`
   - **Exit 0; one test executed, passed.** Viewer's POST `/api/v1/config` returned 403 and GET returned 200. This is one narrow authorization sanity check, **not** the whole endpoint/role/session matrix.

### Existing tests inspected, not run here (Verified source)

- Store CRUD, candidate/commit/rollback, deadlock regressions, expiry/cancel and restart rearm exist (`pkg/cp/config/store_test.go:17,68,130,202,234,270,295,325`). Version tests cover schema bump/reject (`validate_iec104_test.go:237-249`; `store_test.go:354`). These do not establish transactional crash recovery. The hardcoded future version `0.1.8` at `validate_iec104_test.go:245` is future maintenance debt: derive a guaranteed-different version from current authority rather than weakening mismatch assertions on the next schema update.
- API covers export/import and explicit embedded IDS import (`api/http/server_domains_test.go:560,585`), but the former asserts a hostname and is not a clean-instance download/restore with split IDS/secrets. Embedded IDS import **is supported** through Store.Save; the F4 failure is that exported/downloaded artifacts omit split IDS. Backup traversal/sanitization tests exist (`handlers_test.go:496,521`).
- API template tests cover preview-not-save, persistence and upsert (`server_domains_test.go:22,66,147,205`), not the UI's incompatible flat DTO. API TLS/reset tests exist (`dashboard_system_test.go:185,261`), not end-to-end runtime reset convergence.
- `api/http/route_inventory_test.go:144-177` probes every registered route using auth and fails selected 5xx; it accepts 4xx and exempts 501/503. Useful smoke inventory, **not** role, request-schema or documented-operation parity. Existing login/session/CSRF/MFA/remediation/user-role tests are substantial (`handlers_auth_test.go`; `handlers_auth_mfa_test.go`) and must be retained.
- Syslog forwarding fake supplies only one engine-like ID (`pkg/cp/services/runtime_supervision_test.go:121-209`), so it misses mixed-source production shape. Race tests exist (`runtime_supervision_race_test.go:21,101`), not executed. ClamAV fake parses real input frames but appends newline to every response (`av_helpers_test.go:59-106`), masking NUL-response parsing. Renderer/status/process tests are not a substitute for protocol interoperability or service readiness.
- Audit Add/List (`pkg/cp/audit/store_test.go:12`), template list/apply/mode (`pkg/cp/templates/templates_test.go:12-247`) and CLI API/service formatting/confirmed commit (`pkg/cli/cli_test.go:308`; `services_test.go:35`; `api_commands_test.go:174,277,409`) exist. They do not establish a complete CLI↔HTTP operation/role/warning matrix.
- UI scripts provide lint/build/Playwright routes (`ui/package.json:5-10`). No UI command, browser or visual/accessibility inspection was executed; all UI findings are static contract/state-flow evidence, with runtime consequences labeled Inferred.

### NOT RUN / ownership

- Full packages, `go test ./...`, lifecycle race suites, Linux `go build`/`go vet`, lint/dev-verify and coverage gates: **NOT RUN**; audit permits only a few single targeted tests and no source changed. Implementation owners/orchestrator run affected gates after fixes/merge.
- Docker, real DNS/DHCP/NTP/proxy/ClamAV/ICAP/OpenVPN services, kernel/capability tests, clean-image archive restore/reset/upgrade, storage crash/fault injection and multi-instance rollout: **NOT RUN**; disallowed/no isolated runtime authorization in this audit. Explicit follow-up ownership is assigned in section 5.
- Full endpoint RBAC matrix, executable OpenAPI schema validation/generated-client round-trip and UI lint/build/Playwright/accessibility: **NOT RUN**. Static census reviewed registrations, documented method/path entries and handler gates; it does not prove runtime role coverage or OpenAPI syntax validity.
- Static route census result: 165 facade registrations (164 versioned + `/metrics`), 66 documented operations, 101 missing versioned operations. Conditional audit registration is handled separately. This is a bounded source census, not a server launched by this lane.
- Git source status was clean before/after tests and at report completion; HEAD remained `40ec7f81`. No checkout source edits, staging, commits, deployment or deletion performed. Existing report artifacts from other lanes were not modified.

### Scope/operating notes

- The prior lane's checkout-write denial was not retried: all report/probe writes used the user-authorized artifacts directory. This lane encountered no artifact write denial.
- UI audit guidance was read, but its interactive product-context bootstrap would require a checkout write and user question. Those actions were not taken in this read-only/noninteractive task; UI review remains source-based. Its context check created only the artifact-local `impeccable-update-check.json`; no tooling was installed/updated.
- Some exploratory read lookups named nonexistent paths (for example `pkg/cp/config/ics_zero.go`; actual encoding is `ics_json.go`). They produced read errors, were resolved by source search, and do not weaken the cited evidence. No denied write was routed around.
- No user/product blocker prevents this report. Decisions in section 5 (SSH break-glass, secret/archive policy, AV contract, shared-instance roles) require orchestrator/product ownership before implementation, not speculative patches from an audit lane.
