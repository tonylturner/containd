# Graceful signal shutdown exits 0

Ticket 01a0da7f. Branch: fix/post-0.1.30-cleanup (worktree lane; commit on your helper branch).

## Goal
SIGTERM/SIGINT produce an info-level shutdown log and exit code 0. Real run errors still log `fatal error` and exit 1.

## Verified facts
- cmd/containd/main.go:50 `ctx, stop := signal.NotifyContext(context.Background(), SIGINT, SIGTERM)`; modes all/mgmt/engine/cli return err from run functions; main.go:84-87 logs `fatal error` and `os.Exit(1)` on any non-nil err. Live evidence on v0.1.30: `docker compose restart engine` logs `error fatal error {"error": "context canceled"}` and the container exits 1.
- cmd/ngfw-engine/main.go:16-22 and cmd/ngfw-mgmt/main.go:16-22 have the same fatal pattern; check whether they use a signal context and apply the same rule if so.
- Run functions live in pkg/app/mgmt and pkg/app/engine (`Run(ctx, Options)`) and cmd/containd/main.go:253 `runAll`. Do not change their return values; decide at the top level.

## Contract
- A small helper in cmd/containd (e.g. `exitCode(ctx context.Context, err error) int` in its own file) returns 0 when err is nil, or when `errors.Is(err, context.Canceled)` and `ctx.Err() != nil` (the signal fired); otherwise 1. main logs `shutdown complete` at info with the reason for the 0 case and keeps `fatal error` for the 1 case. Reuse the same helper for ngfw-engine/ngfw-mgmt if they have a signal context (a tiny shared internal package is fine if needed; otherwise keep it local).
- Unit test for the helper: nil err, canceled-by-signal, canceled without signal (still 1), real error.

## Fence (write)
cmd/containd/*.go, cmd/ngfw-engine/main.go, cmd/ngfw-mgmt/main.go, and a new test file next to the helper. Nothing under pkg/.

## Validation
- `GOFLAGS=-mod=mod go test ./cmd/...`, `go build ./...`, `GOOS=linux go build ./...`
- `PATH=/tmp/containd-tools:$PATH golangci-lint run ./cmd/...` (cache clean first)
- Report anything wrong with this spec.
