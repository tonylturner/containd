# containd architecture and Docker networking map

Audit date: 2026-09-25. Branch `main` at 302166fc (VERSION 0.1.29). Read-only audit; no code changed.

## 1. Shape of the program

One Go binary, `cmd/containd/main.go`, with modes `all|mgmt|engine|cli|version|healthcheck`.

| Plane | Package(s) | Listens | Role |
|---|---|---|---|
| Data plane | `pkg/dp/*`, `pkg/app/engine` | :8081 (unauthenticated `/internal/*`) | nftables compile/apply, NFQUEUE/AF_PACKET capture, DPI, flow/verdict cache, netlink ownership of interfaces/routes |
| Control plane | `pkg/cp/*` | none | config model, validation, compile Config -> `rules.Snapshot`, services |
| Management plane | `api/http`, `pkg/mp`, `pkg/app/mgmt` | :8080 / :8443, SSH :2222 | REST + UI, candidate/running config store, pushes to engine over `CONTAIND_ENGINE_URL` (default `http://127.0.0.1:8081`) |

`runAll` runs engine and mgmt as goroutines in one process; the compose files run mode `all`.

## 2. The Docker networking design (intentional)

Docker owns L2/L3; containd owns policy inside the topology it is given.

- `deploy/docker-compose.yml` (starter): 8 bridge networks `wan, dmz, lan1..lan6` = `192.168.240.0/24 .. 192.168.247.0/24`. containd is pinned to `.2` on every network (`deploy/docker-compose.yml:147-171`), `gw_priority: 100` on wan so Docker installs the container's default route via the wan bridge, `priority` 1000..300 for attach ordering. dmz/lan* are `internal: true` (no host NAT for workloads on them). Runs as `user: "0"` with NET_ADMIN/NET_RAW/NET_BIND_SERVICE/SYS_TIME and `/dev/net/tun`.
- Docker's bridge gateway `.1` lives in the host netns. A workload container's Docker-installed default route points at `.1`, not at containd. **Traffic traverses containd only when the workload's routes point at containd's `.2`.** The smoke scripts do exactly that with NET_ADMIN in the client containers (`scripts/smoke-dpi.sh:227-234`, `scripts/smoke-forward.sh:174+`): flush main table, add the on-link route, add `default via 172.31.0.2`.
- Consequence documented in `docs/mkdocs/threat-model.md:56,168-170` and `docs/mkdocs/windows-wsl.md`: multi-homed workloads, or workloads still routing via `.1`, bypass the appliance by design.
- `deploy/docker-compose.dev.yml`: builds from source, same subnets/IPs, but the networks are **not** `internal`, and it mounts `/var/run/docker.sock:ro`. The socket is used only for inspection/stats (`api/http/system_inspection.go:277,303`, `api/http/system_stats.go:246`), never for network control.
- `deploy/docker-compose.smoke.yml`: two networks, engine at `172.30.0.2` (wan_net) / `172.31.0.2` (lan_net); lan_client .3, lan_target .4, ot_client .5, wan_server 172.30.0.3, modbus_server 172.30.0.4. Ports 18080/18081/18443/12222, token `devtoken`, `CONTAIND_LAB_MODE=1`.
- `scripts/bootstrap-starter.sh` shifts the starter prefix if it overlaps an existing Docker subnet and exports `CONTAIND_AUTO_*_SUBNET` so autobind still matches.

### Why interface names are unstable and how containd copes

Docker names the container's NICs `eth0..ethN` in alphabetical order of the *network name*, not compose order, and the order can change across restarts. So the logical interface names in config (`wan, dmz, lan1..lan6`, seeded by `config.DefaultConfig`, `pkg/cp/config/config.go:402-436`) must be re-bound to kernel devices at runtime.

- `api/http/interface_autoassign.go`: order = `DefaultPhysicalInterfaces()`; assign by name prefix (`:120`), then by subnet match (`assignBySubnet`, `:138`; env `CONTAIND_AUTO_<X>_SUBNET` then `CONTAIND_<X>_SUBNET`, defaults 192.168.240-247), then default-route iface for wan (`:167`), then index fallback only if allowed (`:184`). Skips veth/br/docker/tun prefixes (`:210`).
- Runs at mgmt boot (`pkg/app/mgmt/mgmt.go:169-186`, after blanking device fields so subnet matching always re-runs) and again on every commit/rollback (`api/http/server.go:565-575`).
- Compile uses `iface.Device`, falling back to `iface.Name` (`pkg/cp/compile/compile.go:~115-127`) to fill `snap.ZoneIfaces`, which becomes the nft `zone_<z>_ifaces` sets.

## 3. Commit -> engine push path

`applyRunningConfig` (`api/http/server.go:558-632`): autobind -> services.Apply -> engine `ConfigureInterfaces` -> `ConfigureRouting` -> `ConfigureServices` -> `Configure(DataPlane)` -> pcap -> load IDS rules -> `compile.CompileSnapshot` -> `engine.ApplyRules`. Infra failures become warnings (header) and rules are still pushed; permission-style nft failures are downgraded to warnings by `isRuntimeApplyWarning`.

Engine side (`pkg/app/engine/runtime_handlers.go:339-395`): `/internal/config` builds a brand-new `engine.Engine` and `Reconfigure`s into it, then `Start`s capture again. If `NFQueueGroup != 0`, capture mode is forced to `nfqueue` (`pkg/dp/engine/engine.go:115-117`).

## 4. Ownership loop (netlink)

`pkg/app/engine/ownership_linux.go`: every 10 s (`:98`) and on any rtnetlink event debounced 350 ms (`:149,158`) it re-applies `netcfg.ApplyInterfaces` (non-replace) and `netcfg.ApplyRouting`.

`pkg/dp/netcfg/interface_apply_linux.go`: enables ip_forward (tolerates EPERM/EROFS for Docker Desktop), bridges/VLANs, DHCP or static. In static mode: `replaceV4 := len(desiredV4) > 0` (`:279`), and when true it **deletes every existing IPv4 address not in the desired set even without `opts.Replace`** (`:280-292`, `skipAddrDeletion :298`). A non-empty `Gateway` installs a default route with NLM_F_REPLACE (`:235`). Managed routes are tagged proto 98; managed rules use priorities 10000-19999.

In the Docker lab the seeded interfaces have **no** `Addresses` and no `Gateway`, so the deletion path is dormant and Docker's `.2` addresses survive. It wakes up the moment someone sets an address on `wan` or a `lan*` in the UI.

## 5. Packet path

1. Kernel nftables, table `inet containd` (`pkg/dp/enforce/enforce.go`). `flush ruleset` on every apply (`:57`). Input chain: policy drop, lo, ct est/rel, icmp, **unconditional `tcp dport 8081 accept`** (`:123`), then per-interface mgmt/SSH/DNS/DHCP/proxy/VPN LocalInput rules.
2. Forward chain: default action policy; `block_hosts` / `block_flows` dynamic sets first; rules with an ICS predicate become `queue num <NFQueueGroup>` and are placed **before** `ct state established accept` (`:165`, `:405`); DNAT accepts; then L4 rules sorted ALLOW-before-DENY then by ID; `log prefix "containd:<id>:<ACTION> " group <NFLogGroup>` on Log:true non-DPI rules.
3. NFQUEUE consumer (`pkg/dp/capture/nfqueue_linux.go`): supervised with 250 ms -> 30 s backoff, 8 retries, MaxQueueLen 1024. The hook **always verdicts NfAccept** (`:155,163,174`). Blocking is retroactive.
4. `handlePacket` (`pkg/dp/engine/engine.go`) -> trackFlow -> ShouldInspect -> verdict cache -> DPI decoders -> `RecordDPIEvents` -> `enforceDPIEvents` (`pkg/dp/engine/policy_eval.go`). In "enforce" mode a DenyDrop becomes `BlockFlowTemp` (`:100`), i.e. an nft `add element block_flows { saddr . daddr . dport timeout 10m }` via `NftUpdater`. So the first out-of-policy PDU passes; subsequent packets of that 3-tuple are dropped by the kernel for 10 minutes. `smoke-dpi.sh` tolerates this.
5. `resolveZonesForFlow` (`policy_eval.go:146-160`) maps IPs to zones by reading the live addresses off the bound devices with `net.InterfaceByName`, so zone attribution depends on Docker's `.2` addresses being present on the devices autobind chose.
6. NAT: postrouting masquerade per NAT source zone -> egress zone (defaults `lan, dmz` -> `wan`, `:256-263`), plus a hardcoded `iifname @zone_wan_ifaces oifname @zone_lan_ifaces masquerade` when any port forward exists (`:267-269`).

## 6. Validation commands

- `bash scripts/dev-verify.sh` (vet, golangci-lint v2, staticcheck, ineffassign, shellcheck, go test, ui lint, mkdocs); `--with-race`, `--with-coverage`, `--with-route-smoke` optional.
- `bash scripts/smoketest` = `smoke-dpi.sh` + `smoke-forward.sh` on `deploy/docker-compose.smoke.yml` (needs Docker).
- CI `.github/workflows/ci.yml`: go, lint-go, docs, ui, docker + quickstart smoke that calls `/interfaces/assign mode=auto`.
- Code boundaries (`docs/mkdocs/code-boundaries.md`): no source file over 1200 lines; handlers in `api/http/*_handlers.go`; validation in `pkg/cp/config/validate*.go`; UI API domain files `ui/lib/api-*.ts`.

## 7. Spots that look off (unverified against a live run)

1. **Address reconcile can fight Docker.** `interface_apply_linux.go:279-292`: any non-empty `Addresses` on a config interface turns on deletion of every other IPv4 on that device, on a 10 s timer and on every netlink event. If a user pins an address that differs from the Docker-assigned `.2`, Docker's address is removed and zone resolution (`resolveZonesForFlow`) and autobind-by-subnet both lose their anchor. `Gateway` likewise REPLACEs the default route Docker installed via `gw_priority`.
2. **`flush ruleset` wipes the whole netns ruleset** (`enforce.go:57`), not just `table inet containd`. Fine in a dedicated container; destructive anywhere else (host mode, shared netns, Docker Desktop tables).
3. **Port-forward masquerade hardcodes `@zone_lan_ifaces`** (`enforce.go:267-269`). Zone sets are only emitted for zones present in `snap.ZoneIfaces` (`:76-90`). A config with port forwards and no zone literally named `lan` should make `nft -f` reject the whole ruleset. The NAT default source zones `lan, dmz` (`:261-263`) reference sets the same way.
4. **Engine API is open on every interface.** `tcp dport 8081 accept` (`enforce.go:123`) is unconditional and `/internal/*` has no auth. On `internal: true` networks that is only reachable from lab peers; on the dev compose (no `internal`) it is reachable from anything routed to the container.
5. **NFQUEUE enforcement is accept-then-block.** First violating PDU is delivered; block lives 10 min in `block_flows`. Correct given the design, but anyone comparing to a drop-on-first-packet expectation will call it a bug.
6. **Dev compose lacks `internal: true`**, so dev-lab workloads keep a working `.1` host-NAT path and quietly bypass containd unless their routes are rewritten like the smoke scripts do.
7. **Reconfigure rebuilds the engine per commit** (`runtime_handlers.go:365-385`): new capture manager, new nflog consumer, new NFQUEUE binding. The supervise loop closes the old handle, but a commit storm re-opens the queue repeatedly; watch for EBUSY under fast repeated commits.
8. **Housekeeping:** untracked build artifacts and module caches in the repo root (`containd`, `*.test`, `ngfw-*`, `.gocache/`, `.gomodcache/`, `.gopath/`, `data/`), all gitignored. Open GitHub issues #17 and #18 are SSH CLI bugs, unrelated to networking.
