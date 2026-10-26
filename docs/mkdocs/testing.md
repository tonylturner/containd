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

For a production static export, `npm run build` also runs the docs prebuild.
To include generated documentation in the export, install Python and the
packages in `docs/requirements-mkdocs.txt`, and put `mkdocs` on `PATH` before
building. The prebuild can reuse existing generated docs when MkDocs is
unavailable; it does not generate missing docs without that toolchain.

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

## What Coverage Does Not Replace

Coverage is only one signal.

It does not replace:

- parser fuzzing
- smoke validation
- performance baselines
- security scans
- real lab-path testing

Treat `scripts/coverage-report.sh` as one verification tool, not the only quality gate.
