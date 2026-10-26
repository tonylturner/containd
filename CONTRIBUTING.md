# Contributing to containd

Bug fixes, tests, documentation and UI improvements are welcome. For larger
features or architectural changes, open an issue to discuss the approach first.
Follow the [Code of Conduct](CODE_OF_CONDUCT.md); report vulnerabilities privately
using [SECURITY.md](SECURITY.md).

## Getting started

1. Fork the repository, clone your fork and create a feature branch from `main`.
2. Install the dependencies below.
3. Make a focused change with tests and user-facing documentation as appropriate.
4. Run the relevant verification checks and submit a pull request with results.

## Development environment

Prerequisites:

- Go 1.26.10+ (see `go.mod` for the exact version).
- Node.js 20+ and npm.
- Docker with modern Docker Compose for appliance builds and smoke tests.
- OpenSSL for the JWT secret-generation command below.
- Python 3.12+ and the pinned MkDocs dependencies for docs **and UI source builds**
  (the UI prebuild embeds the documentation).

Run these commands from the repository root. Activate the virtual environment
in each shell used for docs or UI builds so `mkdocs` is on `PATH`:

```bash
python3 -m venv build/docs-venv
. build/docs-venv/bin/activate
python -m pip install -r docs/requirements-mkdocs.txt
go mod download
(cd ui && npm ci)
```

### Build and run

```bash
# Go binary and UI static export; the subshell preserves the repository cwd.
go build -o containd ./cmd/containd
(cd ui && npm run build)
```

UI source builds require MkDocs on `PATH` and fail if documentation cannot be
generated. `CONTAIND_SKIP_DOCS=1` skips documentation without updating its build
stamp; use it only when a separate build supplies the documentation. The
management Dockerfile builds docs separately and checks the exported docs index.

Running the appliance requires writable runtime storage under `/data` and
external service binaries for enabled services. Use the dev image below for
the packaged Linux runtime, including on Docker Desktop; a native macOS build
is not a host firewall.
See [architecture](docs/mkdocs/architecture.md) and
[services](docs/mkdocs/services.md) for runtime boundaries.

For a source-built appliance with Compose-managed lab networks:

```bash
docker build -f build/Dockerfile.mgmt -t containd/containd:dev .
cp .env.example .env
# This exported value satisfies the Compose secret requirement; keep it private.
export CONTAIND_JWT_SECRET="$(openssl rand -hex 32)"
docker compose --env-file .env -f deploy/docker-compose.dev.yml up -d --build
```

Retain the same secret in your private environment or `.env` for subsequent
starts. Do not commit secrets. Restrict published management ports and rotate
the bootstrap password immediately; see [SECURITY.md](SECURITY.md).
For published-image onboarding and network customization, use the canonical
[Docker Compose guide](docs/mkdocs/docker-compose.md).

### Documentation

Product documentation lives under `docs/mkdocs/`, with navigation in
`docs/mkdocs.yml`. With the dependencies above installed, run from the repo root:

```bash
mkdocs build -f docs/mkdocs.yml
mkdocs serve -f docs/mkdocs.yml
```

The first command builds the static site; the second starts a local preview
server. Use `--strict` when checking documentation changes. Keep one canonical
home per topic and link to it rather than duplicating instructions. Put images
and diagrams under `docs/mkdocs/assets/`; Markdown files at the docs root refer
to them as `assets/<file>`.

### Versioning

- `VERSION` is the canonical release version; release tags must match it exactly
  (`VERSION=0.1.7` pairs with tag `v0.1.7`).
- Add user-facing changes under `Unreleased` in `CHANGELOG.md`. Before tagging,
  add a matching dated release section; the release workflow extracts it as notes.
- `pkg/cp/config.SchemaVersionCurrent` is the config schema version, not the
  release version. Bump it only when stored config compatibility changes.
- Local `go build` defaults to `dev` metadata. Docker builds read `VERSION`
  unless overridden with `--build-arg VERSION=...`.

## Verification

After dependency setup, the standard local baseline is:

```bash
bash scripts/dev-verify.sh
```

It runs Go vet, golangci-lint, staticcheck, ineffassign, ShellCheck, Go tests,
UI lint and a docs build. Install golangci-lint v2 and ShellCheck locally or use
its Docker fallbacks; staticcheck and ineffassign have `go run` fallbacks.
The baseline uses non-race Go tests and is not the complete CI gate.

[CI](.github/workflows/ci.yml) also checks module tidiness, runs the full Go race
suite, scans with curated Semgrep rules, builds the UI and appliance image,
smokes the public Compose quickstart and scans the image with Trivy. To run the
module/race/security checks explicitly from the repository root:

```bash
go mod tidy && git diff --exit-code go.mod go.sum
go test -race ./...
bash scripts/semgrep-verify.sh
```

Run affected checks during development and record exact results or why a check
is not applicable in the PR. Linux-only dataplane tests need a Linux environment;
a native macOS run does not exercise those files. Detailed procedures and
prerequisites are in [testing](docs/mkdocs/testing.md).

Optional local workflows:

- `bash scripts/dev-verify.sh --with-semgrep` adds the curated security scan.
- `bash scripts/dev-verify.sh --with-trivy` adds a repository filesystem scan
  (not the CI image scan).
- `bash scripts/dev-verify.sh --with-race` adds a targeted race package set
  (not the full CI race suite).
- `bash scripts/coverage-report.sh` reports package coverage.
- `bash scripts/smoketest` builds and exercises the local appliance image.
- [Performance guidance](docs/mkdocs/performance.md) covers benchmarks/profiles;
  `bash scripts/complexity-report.sh` supports complexity triage.

## Code standards and boundaries

- Follow Go conventions, including `gofmt` and `go vet`; justify new dependencies.
- Keep data plane (`pkg/dp/`), control plane (`pkg/cp/`) and management plane
  (`pkg/mp/`, `api/`) responsibilities separate. Dataplane snapshots are immutable
  and use atomic swaps.
- Treat facades as routing/assembly surfaces. Put HTTP handlers in the matching
  `api/http/*_handlers.go` domain file and config validation in `validate*.go`.
- Keep `ui/lib/api.ts` a stable facade over domain modules. Extract large
  page-local forms, modals and lookup tables into sibling modules.
- Follow existing Tailwind + shadcn/ui patterns and the dark-first palette.
  Pages use `Shell`; the UI is a static export, without server-side rendering or
  Next.js API routes.
- Keep commits focused with concise imperative subjects and tests for new behavior.

See [code boundaries](docs/mkdocs/code-boundaries.md) for package ownership detail.

## Pull requests and issues

Describe the change, how to test it and any security impact. Update documentation
for user-visible behavior and ensure applicable CI checks pass before merging.
Use GitHub Issues for bugs and feature requests, not private vulnerability reports.

By contributing, you agree your contributions are licensed under the
[Apache License 2.0](LICENSE).
