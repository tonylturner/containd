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

## Forwarding Smoke

`bash scripts/smoke-forward.sh`, also run by `bash scripts/smoketest`, brings
up `deploy/docker-compose.smoke.yml`, installs its own forward policy and NAT
configuration, and checks that:

- allowed LAN-to-WAN traffic arrives, and the WAN server sees the engine's
  WAN address as its source (masquerade);
- the DNAT port forward reaches the LAN target, the target sees the engine's
  LAN address (return-path masquerade), and the DNAT rule's packet counter
  increases;
- each denied flow times out. Every deny probe targets a live listener, and a
  control probe from the listener's own network segment shows that the
  listener answers before the deny is checked.

The script exits 0 when every check passes and 1 when a check fails. It exits
2 on a harness error, such as a missing tool, a failed `docker compose`
command, a listener that does not answer, or a broken client route. A harness
error never counts as a pass.

`bash scripts/smoke-forward-mutations.sh` shows that the checks can fail. It
runs the smoke once with an allow-all forward rule and once with masquerade
for LAN traffic disabled. It passes only when each run fails exactly the
checks that its change breaks. Both scripts accept the isolation variables
described in the smoke fixture README linked below.

## Selecting Tests

| Change | Checks |
|---|---|
| Go package behavior | Focused package tests; use the coverage report to identify untested paths |
| Protocol parsing or stream reassembly | Adjacent malformed-input tests, fuzz targets and benchmarks |
| UI routes or forms | Playwright specs and UI lint; mocked API tests do not validate the live backend |
| Forwarding, NAT or live DPI | `bash scripts/smoketest`; set `SMOKE_INCLUDE_DPI=0` for forwarding only |
| Linux networking or runtime behavior | Tests on Linux with the capabilities required by the package or harness |

Keep regression tests beside the code they exercise, following
[Code Boundaries](code-boundaries.md). Direct statement coverage and live
integration checks measure different things; neither substitutes for the
other. Smoke fixture setup and isolation are documented in
[`test/data-smoke/README.md`](https://github.com/tonylturner/containd/blob/main/test/data-smoke/README.md),
and IEC104 scenarios in
[`test/iec104/README.md`](https://github.com/tonylturner/containd/blob/main/test/iec104/README.md).

## Kernel Tests

`CONTAIND_NETNS_KERNEL_TEST=1` is the one gate of the dataplane kernel tests
in `pkg/dp/engine`, `pkg/dp/enforce`, `pkg/dp/capture`, `pkg/dp/session`,
`pkg/dp/conntrack`, `pkg/dp/dhcpd` and `pkg/dp/netcfg`. Most of them replace
containd's nft tables, routes or links, or create network namespaces, so they
run only with the variable set, in a disposable privileged Linux container.
The `pkg/dp/capture` and `pkg/dp/session` tests also run whenever they run as
root; with the variable set, a missing prerequisite fails them instead of
skipping. Each test's comment gives its container command. The
`pkg/dp/netcfg` management kernel test also needs a TUN device, OpenVPN and
reverse-path filtering; `bash pkg/dp/netcfg/management-kernel.sh` builds that
container and runs it.

## Kernel NFQUEUE Oracle

`TestFirstCommandKernelOracle` in `pkg/dp/engine` routes a client network
namespace through the engine on NFQUEUE to a recording Modbus server. It
requires that the first prohibited command never reaches the server. It needs
a privileged Linux container:

```sh
GOOS=linux CGO_ENABLED=0 go test -c -o build/engine.test ./pkg/dp/engine
docker run --rm --privileged -e CONTAIND_NETNS_KERNEL_TEST=1 \
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
