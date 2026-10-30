# Project Guide

## What this project is

containd is a Docker-based ICS firewall with a management API and UI, plus a
dataplane engine that enforces policy with nftables and inspects industrial
protocols, including IEC 104. The executable in `cmd/containd/main.go` supports
`all`, `mgmt`, `engine`, and `cli` modes.

## Repository map

- `api/` — management HTTP API and engine API clients.
- `cmd/` — executable entry points, including `cmd/containd`.
- `pkg/cp/` — control-plane configuration, policy, identity, and validation.
- `pkg/dp/` — dataplane capture, protocol inspection, enforcement, and state.
- `pkg/app/` — management and engine application assembly.
- `pkg/mp/` — management-plane services, including the SSH server.
- `ui/` — web application and its API client.
- `docs/` — public documentation source, OpenAPI description, and build config.
- `build/` — management and engine Dockerfiles.
- `deploy/` — Docker Compose deployment files.
- `test/` — smoke-test fixtures and IEC 104 test tools.
- `scripts/` — development, verification, and test scripts.

## Working conventions

- Read [Contributing](CONTRIBUTING.md) for setup, workflow, and project standards.
- Keep source files focused on one responsibility and below 1,000 lines.
- Format Go changes with `gofmt`. New Go files include an
  `SPDX-License-Identifier: Apache-2.0` header.
- Keep `docs/openapi.yaml` in sync with registered public routes.
  `api/http/openapi_routes_test.go` checks that both operation sets match.
- Put user-visible changes under `[Unreleased]` in `CHANGELOG.md`, using Keep a
  Changelog headings. Update `README.md` when a change affects its overview or
  contributor-facing entry points.
- Public pages in `docs/mkdocs/` are present-tense documentation for users.
  Maintain their navigation in `docs/mkdocs.yml`.
- Never commit `ui/node_modules/`; it is a local dependency installation.
- Follow [Code Boundaries](docs/mkdocs/code-boundaries.md) for code placement
  and [Testing and Coverage](docs/mkdocs/testing.md) for test selection.

## Validation

Run commands from the repository root unless a command changes directory.
The checks below cover CI validation and additional UI checks. CI details are in
`.github/workflows/ci.yml`; Go lint settings are in `.golangci.yml` (golangci-lint
v2 configuration). CI uses golangci-lint action v7 with version v2.11.

```bash
go mod tidy && git diff --exit-code go.mod go.sum
go test -race ./...
GOOS=linux go build ./...
GOOS=linux go vet ./...
golangci-lint run ./...
bash scripts/semgrep-verify.sh
(cd ui && npm ci && npm run lint && npm run typecheck && npm test && npm run build && npm run test:routes)  # needs MkDocs on PATH
(cd docs && mkdocs build -f mkdocs.yml -d /tmp/containd-docs)
docker buildx build --load --file build/Dockerfile.mgmt --tag containd/containd:ci .
```

The Docker command builds the management image used by CI. The release workflow
also builds `build/Dockerfile.engine` for `linux/amd64` and `linux/arm64`.
CI's lint action invokes golangci-lint against the repository using
`.golangci.yml`. Consult [Testing and Coverage](docs/mkdocs/testing.md) for
Linux-only tests, route smoke prerequisites, and other focused checks.
During development, run focused tests for the changed package before the full
suite. Native macOS builds do not exercise Linux-only dataplane files.
To check the OpenAPI route contract directly, run:

```bash
go test ./api/http -run TestOpenAPIRoutes
```

## Releases

The release workflow runs for pushed `v*` tags and checks that the tag's version
matches `VERSION`. It resolves the tag to a commit but does not require an
annotated tag. The workflow promotes release images to `:latest` only for a
non-prerelease tag whose commit is an ancestor of `main`.
A manual workflow run can promote an existing eligible tag without rebuilding
the images.
