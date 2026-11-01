# Testing And Coverage

Use these workflows to measure package coverage and select checks for a
refactor or feature. See [Contributing](https://github.com/tonylturner/containd/blob/main/CONTRIBUTING.md)
for development prerequisites and the contributor workflow, and
[Performance Baseline](performance.md) for benchmarks and profiles.

## Coverage Workflow

From the repo root:

```bash
bash scripts/coverage-report.sh
```

This runs:

```bash
go test ./... -covermode=count -coverprofile=/tmp/...
```

and prints:

- total statement coverage
- category averages
- the lowest-coverage packages in the repo

Useful options:

```bash
bash scripts/coverage-report.sh --top 20
bash scripts/coverage-report.sh --profile-out /tmp/containd.cover
bash scripts/coverage-report.sh --keep-artifacts
```

## Verification Integration

Coverage is intentionally optional in the broader verification pass because it is slower than the normal development loop.

To include it:

```bash
bash scripts/dev-verify.sh --with-coverage
```

That complements the other validation workflows:

- `bash scripts/dev-verify.sh --with-semgrep`
- `bash scripts/dev-verify.sh --with-route-smoke`
- `bash scripts/smoketest`
- `bash scripts/perf-baseline.sh`
- `bash scripts/verify-published-images.sh` with one mode argument:
  `signature`, `sbom`, or `vulnerabilities`, for the scheduled checks of
  published images (see
  [SBOM](sbom.md#scheduled-checks-of-published-images))

## Release CI Gate

Run the promotion decision tests offline:

```bash
python3 scripts/release-ci-gate.test.py
actionlint .github/workflows/release.yml
```

The tests exercise exact-commit push-to-main matching, rejected PR/unrelated
runs, unsuccessful conclusions, latest attempts, pagination, API errors and the
workflow's bounded polling block with fake API responses and no real sleeps.
No workflow is dispatched and no registry is contacted. See
[Update Policy](update-policy.md#when-latest-moves) for promotion and retry
behavior.

## UI Route Smoke

`npm run test:routes` runs **all Playwright specs** in `ui/tests/`, not only
the route sweep. The route sweep logs in via mocked API responses, visits app
routes, and fails on uncaught page exceptions or console errors.

Run it directly from `ui/`:

```bash
npm ci
npx playwright install chromium
npm run test:routes
```

To run only the route sweep, use `npm run test:routes -- route-smoke.spec.ts`.
The Playwright configuration starts a local Next.js development server on
port 3100; set `PLAYWRIGHT_PORT` to an unused port if another server is
running there, so the tests do not reuse an unrelated server.

Or include it in the broader repo verification pass:

```bash
bash scripts/dev-verify.sh --with-route-smoke
```

This route smoke is intentionally shallow:

- it is meant to catch client crashes, broken route initialization, and obvious page-level regressions
- it is not a replacement for full interactive lab testing
- it specifically exercises malformed firewall/ICS rule shapes so UI regressions like `.join is not a function` fail in CI instead of surfacing only during manual testing

### UI Build And Documentation

For a production static export, `npm run build` also runs the docs prebuild,
which regenerates the embedded documentation on every build. Install Python and
the packages in `docs/requirements-mkdocs.txt` and put `mkdocs` on `PATH`; the
build fails without it. `CONTAIND_SKIP_DOCS=1` skips the docs only for builds
that supply them separately, such as `build/Dockerfile.mgmt`.

## Quickstart Smoke

`bash scripts/smoke-quickstart.sh` is the CI check of the public Compose
quickstart. It starts `deploy/docker-compose.yml`, waits for health, rotates
the bootstrap password and checks that interface assignment, routing and the
monitoring APIs answer. Set `CONTAIND_IMAGE` to the image under test, for
example `containd/containd:dev`; Compose uses its default image otherwise.
`COMPOSE_PROJECT_NAME` defaults to `containd-quickstart`, and a random
`CONTAIND_JWT_SECRET` is generated when unset. The stack publishes the
quickstart ports (8080, 8443 and 2222 by default); move them with the
`CONTAIND_PUBLISH_*_PORT` variables. The script removes the project and its
volumes on exit.
Use a fresh, disposable data directory: the starter bind-mounts `deploy/data`,
which `down -v` does not remove, and the script changes the admin password.

## Forwarding Smoke

`bash scripts/smoke-forward.sh`, also run by `bash scripts/smoketest`, brings
up `deploy/docker-compose.smoke.yml`, saves its own base policy, publishes
port forwards through the management API and commits each policy change.
It checks that:

- allowed LAN-to-WAN traffic arrives, and the WAN server sees the engine's
  WAN address as its source (masquerade);
- the DNAT port forward reaches the LAN target, the target sees the engine's
  LAN address (return-path masquerade), and the DNAT rule's packet counter
  increases;
- publishing with permission inserts a via-forward allow rule; publishing a
  second forward without permission translates packets but does not admit
  them;
- moving a covering DENY from bottom to top and back changes fresh-connection
  delivery according to first-match order, with matching response indices and
  rule order;
- a via-forward rule's historical preview reports unavailable matching, with
  zero matches and no samples;
- deleting the forward removes its generated rule and stops DNAT delivery;
- `show firewall rules` prints order numbers and the via forward when the
  stack exposes a usable CLI path (otherwise a skip reason is logged);
- each denied flow times out. Every deny probe targets a live listener, and a
  control probe from the listener's own network segment shows that the
  listener answers before the deny is checked.

The script exits 0 when every check passes and 1 when a check fails. It exits
2 on a harness error, such as a missing tool, a failed `docker compose`
command, a listener that does not answer, or a broken client route. A harness
error never counts as a pass. Unexpected check failures stop the run before
further policy mutations.

`bash scripts/smoke-forward-mutations.sh` shows that the checks can fail. It
runs the smoke once with an allow-all forward rule and once with masquerade
for LAN traffic disabled. It passes only when each run fails exactly the
checks that its change breaks: the permissive policy defeats all four direct
deny checks and the translate-only forward check; disabling LAN masquerade
defeats only the LAN-to-WAN source-address check. Both scripts accept the
isolation variables described in the smoke fixture README linked below.

## Scanning Gate Smoke

`bash scripts/smoke-av-gate.sh` brings up the same harness, enables the
native clamd with FreshClam off and the EICAR test file's MD5 as its only
custom definition, and commits a scan selection for LAN-to-WAN tcp/8080 and
the port forward's WAN-to-LAN tcp/80. It checks, with the EICAR and clean
objects served by `test/data-smoke/av/`, that:

- under fail-open and fail-closed with the scanner ready, the EICAR
  download and upload are refused with `403` and no EICAR byte reaches the
  client or the origin, clean objects pass whole, the origin sees the
  engine's WAN address;
- under fail-open with the scanner ready, a detection event names the client,
  the inbound port forward is gated the same way with the target seeing the
  engine's LAN address, and an unselected port passes EICAR without a gate event;
- with the backend switched to an ICAP server that refuses connections,
  fail-open passes the tested downloads unscanned, fail-closed refuses downloads
  and uploads while management stays reachable, and a client marked as an ICS
  asset passes the tested downloads under fail-closed;
- an exclude entry wins over the include entry: EICAR passes and the gate
  records no event for it.

Exit codes follow the forwarding smoke. `SMOKE_MUTATION=no-gate` commits an
empty scan selection and must fail the refusal checks. The script accepts
the isolation variables described in the smoke fixture README.

## Remote-Access Smoke

`bash scripts/smoke-remote-access.sh` builds the current checkout's appliance
and an Alpine client image, runs them on private Docker networks in
`10.250.0.0/16` and checks the Linux-kernel VPN paths:

- management answers HTTPS only;
- an issued OpenVPN client handshakes and pings a LAN target, and a revoked
  profile is rejected by the CRL while another client still connects;
- WireGuard completes a kernel handshake and routed ping, and disabling it
  removes only the link containd created;
- both transports, credentials and the CA survive a restart;
- a stored WireGuard fault quarantines only WireGuard, while OpenVPN and
  default-deny enforcement keep working;
- forbidden profile directives are rejected with `400` and change nothing.

Exit 1 is a failed check and exit 2 a prerequisite or harness failure. The
evidence directory holds client keys and profiles; keep it private. Setup is in
[`test/remote-access/README.md`](https://github.com/tonylturner/containd/blob/main/test/remote-access/README.md).

## Selecting Tests

| Change | Checks |
|---|---|
| Go package behavior | Focused package tests; use the coverage report to identify untested paths |
| Protocol parsing or stream reassembly | Adjacent malformed-input tests, fuzz targets and benchmarks |
| UI routes or forms | Playwright specs and UI lint; mocked API tests do not validate the live backend |
| Forwarding, NAT or live DPI | `bash scripts/smoketest`; set `SMOKE_INCLUDE_DPI=0` for forwarding only |
| Scanning gate, AV fail policy or scan selection | `bash scripts/smoke-av-gate.sh` |
| OpenVPN, WireGuard or service fault handling | `bash scripts/smoke-remote-access.sh` |
| Linux networking or runtime behavior | Tests on Linux with the capabilities required by the package or harness |

Keep regression tests beside the code they exercise, following
[Code Boundaries](code-boundaries.md). Direct statement coverage and live
integration checks measure different things; neither substitutes for the
other. Smoke fixture setup and isolation are documented in
[`test/data-smoke/README.md`](https://github.com/tonylturner/containd/blob/main/test/data-smoke/README.md),
and IEC104 scenarios in
[`test/iec104/README.md`](https://github.com/tonylturner/containd/blob/main/test/iec104/README.md).

## Kernel Tests

`CONTAIND_NETNS_KERNEL_TEST=1` opts into most dataplane kernel tests
in `pkg/dp/engine`, `pkg/dp/enforce`, `pkg/dp/capture`, `pkg/dp/session`,
`pkg/dp/conntrack`, `pkg/dp/dhcpd`, `pkg/dp/netcfg` and `pkg/app/engine`.
Most of them replace containd's nft tables, routes or links, or create
network namespaces, so they run only with the variable set, in a disposable
privileged Linux container. The `pkg/dp/capture` and `pkg/dp/session` tests
also run whenever they run as root; with the variable set, a missing
prerequisite fails them instead of skipping. Each test's comment gives its
container command. The `pkg/dp/netcfg` management kernel test also needs a
TUN device, OpenVPN and reverse-path filtering;
`bash pkg/dp/netcfg/management-kernel.sh` builds that container and runs it.

The protection-bind (`TestProtectionBindKernel` in `pkg/dp/engine`) and
scanning-gate kernel tests run together with
`bash scripts/gate-kernel-tests.sh`: the nft steering (`TestGateKernel`) and
the nft load of every golden ruleset (`TestKernelNFTLoadsGoldens`) in
`pkg/dp/enforce`, the gate policy routing (`TestGateRoutingKernel`) in
`pkg/dp/netcfg` and the gate manager (`TestGateManagerKernel`) in
`pkg/app/engine`. The script builds a `golang` image with nftables,
iproute2 and Python, runs it with `NET_ADMIN`, `NET_RAW` and `SYS_ADMIN`
(network namespaces need the last one), keeps the build and module caches in
named Docker volumes, and passes extra arguments to `go test`. It runs the
packages one at a time (`go test -p 1`) because the netcfg and engine tests
install the gate's policy routing in the namespace-global table 104010 and
would remove each other's objects in parallel.

Repeated real-exhaustion protection runs need an explicit longer timeout:

```sh
KERNEL_TEST_RUN='^TestProtectionBindKernel$' bash scripts/gate-kernel-tests.sh -count=20 -timeout 30m -- ./pkg/dp/engine
```

## Interface Address Ownership Tests

The address ownership tests create disposable namespaces and dummy devices.
They cover foreign primary/secondary preservation, owned address changes and
removal, IPv6 link-local preservation, process restart, legacy unmarked addresses,
reserved management protection, and explicit replacement. Run them only in a
disposable privileged Linux container:

```sh
GOOS=linux CGO_ENABLED=0 go test -c -o build/netcfg.test ./pkg/dp/netcfg
docker run --rm --privileged -e CONTAIND_NETNS_KERNEL_TEST=1 \
  -v "$PWD/build:/w" alpine:3.21 sh -c \
  "apk add -q iproute2 && /w/netcfg.test -test.run 'Address.*Kernel' -test.v"
```

`TestOwnershipAddressKernel` in `pkg/app/engine` exercises routine interface
apply and the ownership manager's periodic/event reconcile operation, including
empty intent and cancellation. Run it in the same disposable container with
iproute2, using a compiled engine test binary, or a native Linux Go race runner.

## Kernel NFQUEUE Oracle

`TestFirstCommandKernelOracle` in `pkg/dp/engine` routes a client network
namespace through the engine on NFQUEUE to a recording Modbus server. It
requires that the first prohibited command never reaches the server. It needs
a privileged Linux container:

```sh
GOOS=linux CGO_ENABLED=0 go test -c -o build/engine.test ./pkg/dp/engine
docker run --rm --privileged --sysctl net.ipv4.ip_forward=1 \
  -e CONTAIND_NETNS_KERNEL_TEST=1 \
  -v "$PWD/build:/w" alpine:3.21 sh -c \
  "apk add -q nftables iproute2 && /w/engine.test -test.run FirstCommandKernel -test.v"
```

## What Coverage Does Not Replace

Coverage is only one signal.

It does not replace:

- parser fuzzing
- smoke validation
- performance baselines
- security scans
- real lab-path testing

Treat `scripts/coverage-report.sh` as one verification tool, not the only quality gate.
