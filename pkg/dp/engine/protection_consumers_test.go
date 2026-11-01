// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestProtectionQueueFailureDoesNotBlockNFLog(t *testing.T) {
	for _, required := range []bool{false, true} {
		for _, logReady := range []bool{false, true} {
			name := map[bool]string{false: "optional queue", true: "required queue"}[required] +
				map[bool]string{false: "/logging unavailable", true: "/logging ready"}[logReady]
			t.Run(name, func(t *testing.T) {
				fastRetry(t, 3)
				var binds, stops atomic.Int32
				old := startNFLog
				startNFLog = func(context.Context, uint16, capture.RuleHitSink, func(error), func(capture.SourceEvent)) (func(), error) {
					binds.Add(1)
					stop := func() { stops.Add(1) }
					if !logReady {
						return stop, errBind
					}
					return stop, nil
				}
				t.Cleanup(func() { startNFLog = old })
				e := protectionFixture(t, false)
				c := &bindCapture{fails: 100}
				e.capture = c
				e.nflogGroup = 205
				e.bindProtection(true)
				if !required {
					e.LoadRules(rules.Snapshot{Firewall: []rules.Entry{{
						ID: "allow-https", Action: rules.ActionAllow, Log: true,
						Protocols: []rules.Protocol{{Name: "tcp", Port: "443"}},
					}}})
				}
				e.protectionInstalled(nil, true)
				ctx, cancel := context.WithCancel(context.Background())
				t.Cleanup(e.Close)
				t.Cleanup(cancel)
				if err := e.StartWithRetry(ctx); !errors.Is(err, errBind) {
					t.Fatalf("queue retry did not exhaust: %v", err)
				}
				if c.starts.Load() != 3 {
					t.Fatalf("queue attempts = %d", c.starts.Load())
				}
				if binds.Load() == 0 {
					t.Fatal("queue failure prevented independent NFLOG registration")
				}
				if logReady {
					awaitNFLogState(t, e, "ready")
					if binds.Load() != 1 {
						t.Fatal("queue retries duplicated the live NFLOG consumer")
					}
				} else {
					awaitNFLogState(t, e, "failed")
					if binds.Load() != 3 || stops.Load() != 3 {
						t.Fatalf("NFLOG retry/retirement budget: binds=%d stops=%d", binds.Load(), stops.Load())
					}
				}
				st := e.Protection()
				want := "protecting"
				if required {
					want = "failed"
				} else if !logReady {
					want = "degraded"
				}
				if st.State != want || st.Retryable != (want != "protecting") {
					t.Fatalf("no progress or retry path: %+v", st)
				}
				queue := protectionComponent(t, st, "nfqueue:101")
				if queue.Required != required || queue.State != "failed" {
					t.Fatalf("queue requirement lost: %+v", queue)
				}
				e.Close()
				if logReady && stops.Load() != 1 {
					t.Fatalf("live NFLOG consumer not joined: stops=%d", stops.Load())
				}
			})
		}
	}
}
