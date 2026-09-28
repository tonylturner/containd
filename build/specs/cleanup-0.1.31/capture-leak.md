# Capture consumer and Start-goroutine leak on config commit

Ticket 01a0da15. Branch: fix/post-0.1.30-cleanup (worktree lane; commit on your helper branch).

## Goal
Every config commit must fully stop the previous data-plane run (capture consumer, nflog consumer, metrics ticker) before the new one starts. Goroutine count stays flat across commits. Same design as the nflog fix: the engine owns the run lifecycle; Reconfigure stops synchronously.

## Verified facts (v0.1.30 main)
- pkg/app/engine/runtime_handlers.go:389-393: commit handler calls `dpEngine.Reconfigure(newEngine)` then `go dpEngine.Start(context.Background())`. Nothing ever cancels that context.
- pkg/dp/engine/engine.go:191-224 `Reconfigure`: under lifecycleMu, swaps `e.capture = fresh.capture` and other state, calls the previous `nflogStop` (synchronous), sets `started=false`. It never stops the old capture manager and never cancels the previous Start context.
- pkg/dp/engine/engine.go:226-283 `Start`: `e.capture.Start(ctx, e.handlePacket)`, `startNFLog(ctx, ...)`, then a metrics ticker goroutine (engine.go:271-282) that exits only on `ctx.Done()`. With Background ctx it leaks one goroutine per Start. Live measurement: 15 commit pairs on the smoke stack left 31 `Start.func2` goroutines; pre-fix dump build/specs/nflog-rebind/goroutine-dump.log had 184 plus 2 duplicate afpacket workers.
- pkg/dp/capture/capture.go:64-102 `Manager.Start`: `started` atomic; afpacket mode `startAFPacket` (capture.go:104-122) spawns one `worker.run(ctx)` goroutine per interface and a WaitGroup goroutine; there is no Stop. Nothing cancels the ctx.
- pkg/dp/capture/nfqueue_linux.go:58-66 `startNFQueue` spawns `supervise(ctx, onError)` which retries `runWithRecover` up to nfqueueMaxRetries with backoff and returns on ctx cancel. With the old consumer still bound, each new bind fails and burns the retries.
- pkg/dp/capture/afpacket_linux.go:24 `worker.run(ctx)`: check how it blocks on reads and whether ctx cancel unblocks it promptly (read deadline / socket close on ctx.Done). Stop must not hang on a quiet interface.
- pkg/app/engine/engine.go:99 is the other Start caller (initial start with the process ctx); keep working.
- nflog lifecycle: `startNFLog` returns a stop func; `e.nflogStop` is called by Reconfigure. Keep that behavior (tests in pkg/dp/engine and pkg/dp/capture cover it).

## Contract
- `capture.Manager` gains `Stop()`: cancels the manager's own child context (derived in Start), waits for all consumer goroutines (afpacket workers, nfqueue supervise) to exit, and is idempotent / safe before Start. Start on a stopped manager returns an error or is a no-op; Reconfigure always installs a fresh manager so this does not matter for the engine.
- `Engine` owns a per-Start cancel (`runCancel`) and the capture manager it started. `Start(ctx)` derives `runCtx` from ctx and passes runCtx to capture, nflog, and the ticker. `Reconfigure` (under lifecycleMu): cancel previous runCtx, `prevCapture.Stop()` (synchronous), `prevNflogStop()`, then swap state and reset `started`. Order: stop first, then swap, so the old consumer never feeds the new state mid-swap.
- Add an `Engine.Stop()` only if it falls out naturally; not required.
- The commit handler may keep `context.Background()` since the engine now owns cancellation; do not add a second cancellation path in the handler.

## Fence (write)
pkg/dp/engine/engine.go and its tests, pkg/dp/capture/capture.go, afpacket_linux.go, nfqueue_linux.go, capture_test.go, nfqueue tests, and any new test files in those two packages. Do not touch pkg/app/engine, cmd/, .github/, build/.

## Validation (all must pass, report output)
- `GOFLAGS=-mod=mod go test ./pkg/dp/... -race`
- Goroutine-flatness test in pkg/dp/engine: fake capture whose Start blocks a goroutine until ctx is done; 50 Reconfigure+Start cycles; runtime.NumGoroutine after settling equals baseline within a small tolerance; also assert the fake's Stop was awaited (goroutine gone) before the next Start.
- Linux cross-check: `GOOS=linux go build ./... && GOOS=linux go vet ./pkg/dp/...`, plus `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o /tmp/capture.test ./pkg/dp/capture && docker run --rm -v /tmp:/tmp alpine:3.21 /tmp/capture.test` and the same for pkg/dp/engine.
- `PATH=/tmp/containd-tools:$PATH golangci-lint run ./...` (run `golangci-lint cache clean` first). gofmt is enforced.
- Report anything wrong with this spec, especially if worker.run cannot be unblocked promptly.
