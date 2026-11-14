// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"errors"
	"sync"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/limits"
)

// Capture removes a claimed token from its outstanding map before doing sendmsg.
// This barrier models that interval: another resolution sees ErrUnknownToken,
// although the first submission still owns resident packet storage.
type inflightSettler struct {
	mu               sync.Mutex
	pending          bool
	entered, release chan struct{}
	complete         func(capture.Token, capture.Verdict, error)
	sendError        error
}

func (s *inflightSettler) Settle(rs ...capture.Resolution) []error {
	errs := make([]error, len(rs))
	for i, r := range rs {
		s.mu.Lock()
		claimed := s.pending
		s.pending = false
		s.mu.Unlock()
		if !claimed {
			errs[i] = capture.ErrUnknownToken
			continue
		}
		close(s.entered)
		<-s.release
		s.complete(r.Token, r.Verdict, s.sendError)
		errs[i] = s.sendError
	}
	return errs
}

func testDS34InflightSettlement(t *testing.T) {
	for _, fate := range []string{"submitted", "send-error", "source-flush"} {
		t.Run(fate, func(t *testing.T) {
			h := newAPCIHarness(t, "enforce")
			h.handshake()
			wire := apdu(46, 6, 1, 101, 2)
			head, d := h.send(true, wire[:3])
			if d.Action != capture.Hold {
				t.Fatal(d)
			}
			_, d = h.send(true, wire[3:])
			if d.Action != capture.Repeat || len(d.Resolved) != 1 || d.Resolved[0].Token != head.Token {
				t.Fatalf("release=%+v", d)
			}
			table := h.e.sessions
			table.mu.Lock()
			owner, expected := table.tokenOwnerLocked(head.Token)
			grantCount := table.pairingTotal
			table.mu.Unlock()
			if owner == nil || expected != capture.VerdictRepeat || grantCount != 1 {
				t.Fatalf("release did not activate request before completion: %v/%v/%d", owner, expected, grantCount)
			}
			charge := int64(3) + limits.HeldPacketHeaderAllowanceBytes + limits.HeldTokenMetadataBytes
			if got := h.e.budget.Status().ByCategory["held"]; got != charge {
				t.Fatalf("released packet refunded before submission: %d", got)
			}
			submitter := &inflightSettler{pending: true, entered: make(chan struct{}), release: make(chan struct{}), complete: h.e.hooks.onVerdict}
			if fate == "send-error" {
				submitter.sendError = errors.New("sendmsg failed without a flush")
			}
			table.settler = func() capture.Settler { return submitter }
			done := make(chan struct{})
			var result []error
			go func() {
				result = submitter.Settle(d.Resolved...)
				close(done)
			}()
			var release sync.Once
			t.Cleanup(func() {
				release.Do(func() { close(submitter.release) })
				<-done
			})
			<-submitter.entered
			errs := submitter.Settle(d.Resolved...)
			if len(errs) != 1 || !errors.Is(errs[0], capture.ErrUnknownToken) {
				t.Fatalf("second resolution=%v", errs)
			}
			h.e.hooks.onCaptureError(&capture.ResolutionRejectedError{Token: head.Token, Err: errs[0]})
			table.mu.Lock()
			aborted, grants := owner.state == sessionAborted, table.pairingTotal
			table.mu.Unlock()
			if !aborted || grants != 0 || h.e.budget.Status().ByCategory["held"] != charge {
				t.Fatal("rejection failed to abort grants or refunded in-flight residency")
			}
			if fate == "source-flush" {
				table.onSourceDown(head.Token.Generation())
				if h.e.budget.Status().ByCategory["held"] != 0 {
					t.Fatal("explicit generation flush retained residency")
				}
			}
			release.Do(func() { close(submitter.release) })
			<-done
			if len(result) != 1 || !errors.Is(result[0], submitter.sendError) {
				t.Fatalf("first submission=%v want %v", result, submitter.sendError)
			}
			want := int64(0)
			if fate == "send-error" {
				want = charge
			}
			if got := h.e.budget.Status().ByCategory["held"]; got != want {
				t.Fatalf("completion residency=%d want %d", got, want)
			}
			table.onSourceDown(head.Token.Generation())
			table.onVerdict(head.Token, capture.VerdictDrop, capture.ErrTokenFlushed)
			if h.e.budget.Status().ByCategory["held"] != 0 {
				t.Fatal("flush or duplicate completion leaked residency")
			}
			h.e.Close()
			if h.e.budget.Status().InUse != 0 {
				t.Fatal("shutdown retained session storage")
			}
		})
	}
}
