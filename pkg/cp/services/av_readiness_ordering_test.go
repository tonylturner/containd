// SPDX-License-Identifier: Apache-2.0
package services

import (
	"bytes"
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/avscan"
)

func TestAVReadinessCanaryInvalidationOrdering(t *testing.T) {
	for _, newerCanary := range []bool{false, true} {
		t.Run(map[bool]string{false: "canary before loss", true: "canary after loss"}[newerCanary], func(t *testing.T) {
			state := avDirectionHealth{}
			state.publishCanary(1, true, "")
			seq := uint64(2)
			if newerCanary {
				seq = 4
			}
			// Exercise both completion orders, including a successful canary
			// that finishes before an older failure finally arrives.
			for _, lossFirst := range []bool{false, true} {
				s := state
				if lossFirst {
					s.invalidateScan(3, "lost transport")
				}
				s.publishCanary(seq, true, "")
				if !lossFirst {
					s.invalidateScan(3, "lost transport")
				}
				if s.healthy != newerCanary {
					t.Fatalf("lossFirst=%v: %+v", lossFirst, s)
				}
			}
		})
	}
}

func TestAVReadinessTransportLossAfterNewerOptions(t *testing.T) {
	var phase atomic.Int32
	var uploads, downloads atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	s := startReadinessICAP(t, "127.0.0.1:0", func(req icapRequest) string {
		p := phase.Load()
		if p == 1 && req.Method == icapREQMOD && !bytes.Equal(req.Body, []byte(avCanaryPayload)) {
			close(entered)
			<-release
			return "ICAP/1.0 500 Error\r\n" // complete body read, truncated transport response
		}
		if bytes.Equal(req.Body, []byte(avCanaryPayload)) {
			if req.Method == icapREQMOD {
				uploads.Add(1)
			} else {
				downloads.Add(1)
			}
			if p == 2 && req.Method == icapRESPMOD {
				return icapCleanReply
			} // download scanner bypasses after recovery
		}
		return healthyReadinessReply(req)
	})
	defer unblock()
	m := newTestAVManager(t, AVOptions{})
	cfg := readinessICAPConfig(s)
	if err := m.Apply(applyCtx(t), cfg); err != nil {
		t.Fatal(err)
	}
	m.stopObserver()
	phase.Store(1)
	done := make(chan avscan.Result, 1)
	go func() { done <- m.Scan(context.Background(), uploadObject([]byte("object"))) }()
	select {
	case <-entered:
	case <-time.After(readinessTestBound):
		t.Fatal("scan not received")
	}
	// A newer capability-only observation overtakes the failing scan.
	if st := m.Status(context.Background()); st["ready"] != true {
		t.Fatal(st)
	}
	phase.Store(2)
	unblock()
	if res := <-done; res.Verdict != avscan.Unscanned {
		t.Fatal(res)
	}
	assertAVReady(t, m, false)
	ready, _, why := m.observeBackend(context.Background(), cfg, m.backendEpoch, true, true)
	t.Logf("recovery ready=%v why=%q upload canaries=%d download canaries=%d", ready, why, uploads.Load(), downloads.Load())
	if ready {
		t.Fatal("readiness resurrected with download bypassing and no fresh download canary")
	}
}

func TestAVReadinessOrdinaryScansCannotPreservePreLossCanaries(t *testing.T) {
	var phase atomic.Int32
	var canaries atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	s := startReadinessICAP(t, "127.0.0.1:0", func(req icapRequest) string {
		p := phase.Load()
		if p == 1 && req.Method == "OPTIONS" {
			close(entered)
			<-release
			return "ICAP/1.0 500 Error\r\n"
		}
		if bytes.Equal(req.Body, []byte(avCanaryPayload)) {
			canaries.Add(1)
			if p == 2 {
				return icapCleanReply
			}
		}
		return healthyReadinessReply(req)
	})
	defer unblock()
	m := newTestAVManager(t, AVOptions{})
	cfg := readinessICAPConfig(s)
	if err := m.Apply(applyCtx(t), cfg); err != nil {
		t.Fatal(err)
	}
	m.stopObserver()
	phase.Store(1)
	done := make(chan struct{})
	go func() { defer close(done); m.Status(context.Background()) }()
	select {
	case <-entered:
	case <-time.After(readinessTestBound):
		t.Fatal("OPTIONS not received")
	}
	// Neither clean ordinary object proves that EICAR detection still works.
	for _, obj := range []avscan.Object{uploadObject([]byte("upload")), scanObject([]byte("download"))} {
		if res := m.Scan(context.Background(), obj); res.Verdict != avscan.Clean {
			t.Fatal(res)
		}
	}
	phase.Store(2)
	unblock()
	<-done
	assertAVReady(t, m, false)
	ready, _, why := m.observeBackend(context.Background(), cfg, m.backendEpoch, true, true)
	t.Logf("recovery ready=%v why=%q total canaries=%d", ready, why, canaries.Load())
	if ready {
		t.Fatal("readiness resurrected after transport loss with bypassing backend and zero fresh canaries")
	}
}

// Recovery must make progress even when clean traffic overtakes each canary.
func TestAVReadinessOrdinaryTrafficCannotStarveRecoveredCanary(t *testing.T) {
	var phase atomic.Int32
	entered, release := make(chan struct{}, 1), make(chan struct{}, 1)
	s := startReadinessICAP(t, "127.0.0.1:0", func(req icapRequest) string {
		if req.Method == "OPTIONS" {
			return icapReadyReply
		}
		switch phase.Load() {
		case 1:
			return icapErrorReply
		case 2:
			if bytes.Equal(req.Body, []byte(avCanaryPayload)) {
				entered <- struct{}{}
				<-release
			}
		}
		return healthyReadinessReply(req)
	})
	defer close(release)
	m := newTestAVManager(t, AVOptions{})
	cfg := readinessICAPConfig(s)
	cfg.HTTPDownload = false
	if err := m.Apply(applyCtx(t), cfg); err != nil {
		t.Fatal(err)
	}
	m.stopObserver()
	lost := 0
	for range 3 {
		phase.Store(1)
		if res := m.Scan(context.Background(), uploadObject([]byte("failure"))); res.Verdict != avscan.Unscanned {
			t.Fatal(res)
		}
		assertAVReady(t, m, false)
		phase.Store(2)
		done := make(chan bool, 1)
		go func() { r, _, _ := m.observeBackend(context.Background(), cfg, m.backendEpoch, false, true); done <- r }()
		select {
		case <-entered:
		case <-time.After(readinessTestBound):
			t.Fatal("canary not received")
		}
		if res := m.Scan(context.Background(), uploadObject([]byte("clean"))); res.Verdict != avscan.Clean {
			t.Fatal(res)
		}
		release <- struct{}{}
		if !<-done {
			lost++
		}
	}
	phase.Store(3)
	ready, _, why := m.observeBackend(context.Background(), cfg, m.backendEpoch, false, true)
	if !ready {
		t.Fatalf("quiescent control did not recover: %s", why)
	}
	t.Logf("successful EICAR canaries discarded under clean traffic: %d/3; quiescent recovery=%v", lost, ready)
	if lost != 0 {
		t.Fatal("healthy backend stayed unready whenever newer clean traffic overtook its canary")
	}
}
