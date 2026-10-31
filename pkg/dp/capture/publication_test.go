// SPDX-License-Identifier: Apache-2.0

package capture

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func publicationWait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("publication operation did not finish")
	}
}

func TestPublicationFenceThroughVerdict(t *testing.T) {
	for _, deferred := range []bool{false, true} {
		name := "immediate"
		if deferred {
			name = "deferred"
		}
		t.Run(name, func(t *testing.T) {
			var fence sync.RWMutex
			submitting, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			comp := newCompleter(nil, nil)
			defer comp.close()
			g := newGeneration(func(uint32, Verdict, uint32) error {
				close(submitting)
				<-release
				return nil
			}, comp, nil)
			g.fence = &fence
			var tok Token
			handler := func(pkt Packet) Decision {
				if !pkt.PublicationPinned() {
					t.Error("handler does not pin policy")
				}
				if fence.TryLock() {
					fence.Unlock()
					t.Error("handler does not hold the publication lock")
				}
				tok = pkt.Token
				if deferred {
					return Decision{Action: Hold}
				}
				return Decision{Action: Repeat, Mark: 0x1234}
			}
			if deferred {
				g.deliver(1, Packet{}, handler)
			}
			go func() {
				defer close(done)
				if deferred {
					errs := make([]error, 1)
					g.settle([]Resolution{{Token: tok, Verdict: VerdictRepeat, Mark: 0x1234}}, []int{0}, errs)
					if errs[0] != nil {
						t.Errorf("deferred send: %v", errs[0])
					}
				} else {
					g.deliver(1, Packet{}, handler)
				}
			}()
			publicationWait(t, submitting)
			if fence.TryLock() {
				fence.Unlock()
				t.Error("writer passed an unfinished verdict")
			}
			close(release)
			publicationWait(t, done)
			if !fence.TryLock() {
				t.Fatal("verdict leaked publication pin")
			}
			fence.Unlock()
		})
	}
}

func TestPublicationRetirementDoesNotSendOrFailSource(t *testing.T) {
	var fence sync.RWMutex
	var mu sync.Mutex
	completed := map[Token]int{}
	comp := newCompleter(func(tok Token, verdict Verdict, err error) {
		mu.Lock()
		defer mu.Unlock()
		completed[tok]++
		if verdict != VerdictDrop || !errors.Is(err, ErrTokenFlushed) {
			t.Errorf("retirement = %v %v", verdict, err)
		}
	}, nil)
	defer comp.close()
	g := newGeneration(func(uint32, Verdict, uint32) error {
		t.Error("retirement sent a kernel verdict")
		return nil
	}, comp, nil)
	g.fence = &fence
	var tok Token
	g.deliver(7, Packet{}, func(pkt Packet) Decision {
		tok = pkt.Token
		return Decision{Action: Hold}
	})
	fence.Lock()
	g.retireFlushed()
	g.retireFlushed()
	fence.Unlock()
	errs := make([]error, 1)
	g.settle([]Resolution{{Token: tok, Verdict: VerdictRepeat}}, []int{0}, errs)
	if !errors.Is(errs[0], ErrUnknownToken) || g.failure() != nil {
		t.Fatalf("late verdict = %v, source = %v", errs, g.failure())
	}
	comp.flush()
	mu.Lock()
	defer mu.Unlock()
	if len(completed) != 1 || completed[tok] != 1 {
		t.Fatalf("completions = %v", completed)
	}
}
