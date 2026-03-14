# Contributing to containd

Thank you for your interest in contributing to containd. This document covers the process for contributing to this project.

## Getting Started

1. Fork the repository and clone your fork.
2. Set up the development environment (see below).
3. Create a feature branch from `main`.
4. Make your changes, write tests, and verify everything passes.
5. Submit a pull request.

## Development Environment

### Prerequisites

- Go 1.25.8+ (see `go.mod` for exact version)
- Node.js 20+ and npm
- Docker and Docker Compose
- Python 3.12+ (for docs builds only)

### Building

```bash
# Go binary
go build ./cmd/containd

# UI (static export)
cd ui && npm ci && npm run build

# Docker image
docker build -f build/Dockerfile.mgmt -t containd/containd:dev .

# Full appliance via Compose
cp .env.example .env
docker compose --env-file .env -f deploy/docker-compose.dev.yml up -d --build
```

### Versioning

- `VERSION` is the canonical release version for the repo.
- Release tags must match `VERSION` exactly, for example `VERSION=0.1.7` pairs with tag `v0.1.7`.
- Add a matching `CHANGELOG.md` section before tagging a release. The release workflow publishes that section as the GitHub release notes.
- `pkg/cp/config.SchemaVersionCurrent` is the config schema version, not the release version. Bump it only when stored config compatibility changes.
- Local `go build` defaults to `dev` build metadata. Docker builds read `VERSION` automatically unless you override `--build-arg VERSION=...`.

### Running Tests

```bash
# Go unit tests
go test ./...

# UI lint
cd ui && npm run lint

# Smoke tests (builds and validates the local appliance image)
bash scripts/smoketest
```

### Local Verification

For the standard contributor verification flow, use:

```bash
bash scripts/dev-verify.sh
```

This runs:

- `go vet ./...`
- `golangci-lint run` (with a Docker fallback if the binary is not installed locally)
- `staticcheck ./...` (with a `go run` fallback if the binary is not installed locally)
- `ineffassign ./...` (with a `go run` fallback if the binary is not installed locally)
- `shellcheck -x` on the repo shell entrypoints (with a Docker fallback if the binary is not installed locally)
- `go test ./...`
- `cd ui && npm run lint`
- `mkdocs build -f docs/mkdocs.yml`

To include the repo filesystem vulnerability scan too:

```bash
bash scripts/dev-verify.sh --with-trivy
```

To include the curated Semgrep security scan too:

```bash
bash scripts/dev-verify.sh --with-semgrep
```

For dataplane benchmark and profile work:

```bash
bash scripts/perf-baseline.sh
bash scripts/perf-baseline.sh --profile
```

For complexity triage during refactors:

```bash
bash scripts/complexity-report.sh
```

## Code Standards

### Go

- Follow standard Go conventions (`gofmt`, `go vet`).
- Prefer `bash scripts/dev-verify.sh` before pushing so local verification matches the expected repo baseline.
- Maintain strict separation between data plane (`pkg/dp/`), control plane (`pkg/cp/`), and management plane (`pkg/mp/`, `api/`).
- Data plane snapshots are immutable; use atomic swaps.
- Avoid introducing new dependencies without justification.

### TypeScript / React

- Follow the existing Tailwind + shadcn/ui patterns.
- Dark-mode-first; use the existing color palette (see `globals.css` and Tailwind config).
- All pages use the `Shell` layout component for consistent navigation.
- Static export only — no server-side rendering or API routes in Next.js.

### General

- Write tests for new functionality.
- Keep commits focused: one logical change per commit.
- Write clear commit messages: imperative mood, concise summary, body if needed.

## Code Boundaries

The main contributor-facing facades now have explicit ownership boundaries documented in [docs/mkdocs/code-boundaries.md](docs/mkdocs/code-boundaries.md).

When adding new code:

- Treat facade files as routing/assembly surfaces, not catch-all implementation files.
- Add new HTTP endpoints to the matching `api/http/*_handlers.go` domain file, not back into `api/http/server.go`.
- Add config validation to the matching `pkg/cp/config/validate*.go` file, not back into `pkg/cp/config/config.go`.
- Add new UI API endpoints to the matching `ui/lib/api-*.ts` domain file, and keep `ui/lib/api.ts` as the stable facade.
- Move large page-local forms, modals, and lookup tables into sibling modules before growing page files further.

## Local Verification

Recommended local verification flows:

- `bash scripts/dev-verify.sh`
- `bash scripts/dev-verify.sh --with-semgrep`
- `bash scripts/dev-verify.sh --with-coverage`
- `bash scripts/smoketest`
- `bash scripts/perf-baseline.sh`

For coverage-specific inspection, use:

- `bash scripts/coverage-report.sh`

## Pull Request Process

1. Ensure CI passes (Go tests, UI lint/build, Docker build).
2. Update documentation if your change affects user-facing behavior.
3. Add a brief description of the change and how to test it.
4. PRs require at least one review before merging.

## What to Contribute

Good first contributions:

- Bug fixes with a clear reproduction path.
- Test coverage for untested code paths.
- Documentation improvements.
- UI polish (loading states, error handling, accessibility).

Larger contributions (new features, architectural changes) — please open an issue first to discuss the approach before investing significant effort.

## Reporting Issues

- Use GitHub Issues for bugs and feature requests.
- For security vulnerabilities, see [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
