# Fix: nflog consumer dies after a config commit (re-bind races the previous unbind)

Ticket 01a0d9ef-eb50-7f51-b14c-777a406020ec. Branch `fix/nflog-rebind-race` (already checked out in
/Users/tturner/Documents/GitHub/containd; work there directly, no worktree). Bug report:
/Users/tturner/Documents/containd-bug-report.md (read it first; its mechanism is confirmed below).

## Verified facts (main @ 302166fc)

- `pkg/app/engine/runtime_handlers.go:370-391`: every `POST /internal/config` builds a fresh
  `engine.New(...)`, calls `dpEngine.Reconfigure(newEngine)`, then `go dpEngine.Start(context.Background())`.
  `engine.Config` has no error/log hook; `capture.Config{Interfaces: ...}` is built without `OnError`, so
  capture errors are dropped on the floor. The handler has a `*zap.SugaredLogger`.
- `pkg/dp/engine/engine.go:49`: `nflogCancel context.CancelFunc`. `Reconfigure` (`:181-210`) grabs it under
  `flowMu`, swaps state, calls `prevNflogCancel()` fire-and-forget at `:207`, sets `started=false` at `:209`.
- `Engine.Start` (`:212-255`): `capture.Start`, then if `nflogGroup != 0` creates a child ctx, stores the
  cancel, calls `capture.StartNFLog(...)`. On error it cancels, clears, and appends a
  `service.nflog.unavailable` event to the (engine-local) event store. No retry, nothing in the process log.
- `pkg/dp/capture/nflog_linux.go:50-90`: `StartNFLog` opens `nflog.Open`, spawns `go func(){ <-ctx.Done(); nf.Close() }()`
  (`:67-70`), registers with `RegisterWithErrorFunc(ctx, hook, errFn)`; `errFn` always returns 0.
  `pkg/dp/capture/nflog_other.go:25` is the non-linux stub.
- go-nflog v2.3.0 (`$(go list -m -f '{{.Dir}}' github.com/florianl/go-nflog/v2)/nflog.go`):
  `Close()` = `Con.Close()` then `wg.Wait()`. The wg is held by the deadline goroutine that only exits after
  `ctx.Done()`, so **`Close()` deadlocks unless the ctx was cancelled first**. The deferred group UNBIND
  (`:215-223`) runs after the receive loop exits; the receive loop only exits when `ctx.Err() != nil` is
  observed at the top of the loop, i.e. after `Receive()` returns (deadline or closed socket) and `errfn`
  returns 0. Kernel side, closing the netlink socket releases the group instance (NETLINK_URELEASE
  notifier in nfnetlink_log), so a *completed* `Close()` is sufficient for the group to be free.
- The race: Reconfigure returns before the old socket is closed; the new Start binds group N on a new
  socket; kernel returns EPERM because the instance is owned by the old portid; the old consumer then
  unbinds and the group is orphaned. Reproduced by rangerdanger in 1/3 local runs with two commits ~0-3 s apart.
- Existing test seams: `pkg/dp/capture/nfqueue_linux.go:26` uses an injectable `runFn`;
  `pkg/dp/capture/nfqueue_linux_test.go` tests supervise without kernel access. `pkg/dp/engine/engine_test.go`
  builds engines with `New(Config{Capture: capture.Config{Interfaces: []string{"lo"}}})` (lo0 fallback on mac).
- Lint: `.golangci.yml` v2 config; `bash scripts/dev-verify.sh` is the full gate. Dev host is macOS; only
  the linux build tag paths touch netlink. Docker Desktop (linuxkit 6.12) is available for the compose smoke.

## Goal

After `Reconfigure` returns, the previous nflog consumer's socket is closed and the kernel group is free, so
the following `Start` binds cleanly. No fire-and-forget teardown, no retry loop papering over the window.

## Design (contract)

1. `capture.StartNFLog(ctx, group, sink, onErr) (stop func(), err error)`.
   - `stop` cancels the internal child context and then calls `nf.Close()`, returning only once `Close`
     has returned (socket closed → group released). Idempotent; safe to call more than once.
   - Remove the async close goroutine at `nflog_linux.go:67-70`; `stop` owns the close. On register error,
     cancel + close before returning the error.
   - `errFn` returns non-zero once the ctx is done (mirror `nfqueue_linux.go:179-187`) so the receive loop
     exits promptly and does not spin on a closed socket.
   - `nflog_other.go` stub returns a no-op stop and nil.
   - `StartNFLog` still returns `(nil-safe no-op stop, nil)` when `group == 0 || sink == nil`.
2. Engine (`pkg/dp/engine/engine.go`): replace `nflogCancel context.CancelFunc` with `nflogStop func()`.
   `Reconfigure` takes the previous stop under `flowMu`, swaps state, releases the lock, then **calls the
   stop and waits for it** before setting `started=false` and returning. `Start` stores the returned stop.
   Keep the ordering guarantee simple and stated in the comment: Reconfigure returns ⇒ old group released.
3. Process-log visibility: add `OnError func(error)` to `engine.Config`; `engine.New` passes it through to
   `capture.Config.OnError` when that is nil, and `Start` calls it (in addition to appending the
   `service.nflog.unavailable` event) when nflog registration fails. Wire it in
   `runtime_handlers.go` config handler and in `pkg/app/engine/engine.go:83` (`initialEngineConfig`) using
   the existing zap logger at error level.
4. Tests:
   - Unit (all platforms): a package-level seam in `pkg/dp/engine` (e.g. `var startNFLog = capture.StartNFLog`)
     so a test can install a fake that records bind/stop ordering. Loop `Reconfigure(fresh)` + `Start(ctx)`
     ≥100 times and assert (a) a new bind never begins before the previous stop has completed and
     (b) `service.nflog.unavailable` is never appended. Use a fake whose stop has a small sleep to make
     the old fire-and-forget ordering fail deterministically.
   - Unit for `StartNFLog` stop semantics in `pkg/dp/capture` if you can do it without the kernel; otherwise
     a linux integration test with a real group, skipped unless running as root / CAP_NET_ADMIN (match the
     style of the existing linux-gated tests in the repo; grep for `Skip` in `pkg/dp/**/*_linux_test.go`).
5. `CHANGELOG.md` `## [Unreleased]` → `### Fixed` entry in the existing voice (see the DNP3 entry above it).

## Fences (write)

- `pkg/dp/capture/nflog_linux.go`, `pkg/dp/capture/nflog_other.go`, `pkg/dp/capture/*nflog*_test.go`
- `pkg/dp/engine/engine.go`, `pkg/dp/engine/*_test.go` (new nflog lifecycle test file preferred)
- `pkg/app/engine/runtime_handlers.go`, `pkg/app/engine/engine.go` (only the OnError wiring)
- `CHANGELOG.md`
Everything else is read-only. Do not touch the NFQUEUE consumer lifecycle (see note below).

## Validation

- `GOFLAGS=-mod=mod go build ./... && go vet ./... && go test ./pkg/dp/... ./pkg/app/...`
- `GOOS=linux GOARCH=amd64 go build ./...` and `GOOS=linux go vet ./pkg/dp/capture/ ./pkg/dp/engine/` (linux tag paths must compile)
- `bash scripts/dev-verify.sh` (full gate; report any pre-existing failures separately)
- Commit on `fix/nflog-rebind-race` with a conventional message like
  `fix(engine): make nflog consumer teardown synchronous so re-bind after commit cannot race the unbind`.
  Do not push. Author identity is the repo's configured git user; no AI attribution anywhere.

## Out of scope, but report on it

`Reconfigure` swaps `e.capture` without stopping the old capture manager, and the NFQUEUE consumer's ctx is
`context.Background()` from the handler, so it looks like each commit leaks the old NFQUEUE consumer (still
calling the live `e.handlePacket`) while the new one fails its bind with EPERM through 8 supervise retries.
Confirm or refute that reading in your report with file:line evidence; do not change it.

Report at the end: what is wrong or ambiguous in this spec, what you changed, validation output, and the
NFQUEUE finding.
