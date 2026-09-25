# Clear HIGH/CRITICAL trivy findings (ticket 01a0da2f-5410-71f1-93c1-2699869556d4)

## Goal
Bring the image scan (`trivy image --severity HIGH,CRITICAL containd/containd:dev`, the CI gate in
.github/workflows/ci.yml "Trivy vulnerability scan") and the repo scan (`bash scripts/dev-verify.sh --with-trivy`)
back to zero HIGH/CRITICAL by upgrading dependencies. No behavior changes. No suppressions in .trivyignore
unless a finding has no upstream fix (then document why in the file, per its header).

## Verified facts (2026-09-25, branch fix/nflog-rebind-race @ b9e37bfb)
- go.mod: `go 1.25.10`; golang.org/x/crypto v0.49.0 (go.mod:22), x/net v0.52.0 (:23), x/text v0.35.0 indirect (:70).
- Trivy findings in the Go binary (26 HIGH): x/crypto CVE-2026-39828 (fixed 0.52.0), x/net CVE-2026-25681,
  x/text CVE-2026-56852 (fixed 0.39.0), stdlib CVE-2026-27145 (fixed 1.25.11 / 1.26.4).
- Base images: build/Dockerfile.mgmt:21 and build/Dockerfile.engine:6 use `golang:1.25.10-alpine`;
  runtime is `cgr.dev/chainguard/wolfi-base:latest@sha256:52e71f61…` (Dockerfile.mgmt:46,:51; Dockerfile.engine:23).
  Wolfi findings: busybox CVE-2023-39810 (fixed 1.37.0-r58), libcrypto3/libssl3 CVE-2026-31789 CRITICAL (fixed 3.6.2-r0).
  Refresh the wolfi digest to the current `latest` (docker pull, then pin the new sha256) and/or `apk upgrade` in the
  runtime stage; keep the digest pin.
- Dockerfile.mgmt also uses node:20-alpine (:12), python:3.12-alpine (:3), alpine:3.20 (:37), envoyproxy/envoy:v1.31.2 (:49).
  Bump only if trivy flags them.
- UI: ui/package.json next "15.5.10" (:18). Findings: next CVE-2026-75604 CRITICAL (fixed 15.5.24), CVE-2026-44573 HIGH
  (fixed 15.5.16), nanoid CVE-2026-67213 (fixed 3.3.18 / 5.1.6). UI is a static export (`output: "export"` in
  ui/next.config.js) built into the image by build/Dockerfile.mgmt. Stay on the 15.5.x line.
- CI on main is green only because the CVEs post-date the last run (2026-06-02).

## Fence (write)
go.mod, go.sum, build/Dockerfile.mgmt, build/Dockerfile.engine, ui/package.json, ui/package-lock.json,
CHANGELOG.md (one Unreleased "Security"/"Changed" bullet), .trivyignore (only with justification).
Nothing else. Do not touch pkg/, api/, ui/app, ui/components, scripts/.

## Validation (all must pass; report exact commands and results)
1. `export PATH=/tmp/containd-tools:$PATH GOFLAGS=-mod=mod; bash scripts/dev-verify.sh --with-trivy --with-race`
   (do NOT put ~/go/bin on PATH: that staticcheck is built with go1.24 and fails; the script's `go run` fallback works).
   Expect "All requested verification steps passed" and trivy fs Total 0 HIGH/CRITICAL for both go.mod and
   ui/package-lock.json.
2. `GOOS=linux GOARCH=amd64 go build ./... && GOOS=linux go vet ./pkg/dp/...`
3. `docker compose -f deploy/docker-compose.smoke.yml build engine` then
   `trivy image --exit-code 1 --severity HIGH,CRITICAL --ignorefile .trivyignore --format table containd/containd:dev`
   → exit 0. Also `docker build -f build/Dockerfile.engine -t containd/engine:qa .` builds.
4. `cd ui && npm ci && npm run lint && npm run build && PLAYWRIGHT_PORT=3101 npm run test:routes` → 34 passed
   (port 3100 is held by an unrelated process on this host; PLAYWRIGHT_PORT is honored by ui/playwright.config.ts).
5. `SMOKE_BUILD=0 bash scripts/smoketest` → DPI 7/7 and forwarding 9/9 (engine on localhost:18081, mgmt 18080).
6. `go mod tidy && git diff --exit-code go.mod go.sum`.

## Commit
One commit per concern is fine (go deps / images / ui deps), author identity as configured, conventional
`chore(deps): …` / `build(docker): …` subjects. Do not push. Report anything in this spec that is wrong.
