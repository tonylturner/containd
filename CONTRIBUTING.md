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

- Go 1.25+ (see `go.mod` for exact version)
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
docker build -f Dockerfile.mgmt -t containd/containd:dev .

# Full appliance via Compose
cp .env.example .env
docker compose up -d --build
```

### Running Tests

```bash
# Go unit tests
go test ./...

# UI lint
cd ui && npm run lint

# Smoke tests (requires running Compose stack)
bash scripts/smoke-forward.sh
```

## Code Standards

### Go

- Follow standard Go conventions (`gofmt`, `go vet`).
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
