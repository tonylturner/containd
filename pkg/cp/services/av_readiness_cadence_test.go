// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package services

import (
	"bytes"
	"context"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/avscan"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestAVReadinessOptionsTTL(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  time.Duration
	}{
		{"", time.Second}, {"0", time.Second}, {"-1", time.Second}, {"garbage", time.Second},
		{"2", 2 * time.Second}, {"30", avOptionsTTLCap}, {"3600", avOptionsTTLCap}, {"4294967295", avOptionsTTLCap},
	} {
		t.Run(strconv.Quote(tc.value), func(t *testing.T) {
			s := startReadinessICAP(t, "127.0.0.1:0", func(icapRequest) string {
				return "ICAP/1.0 200 OK\r\nMethods: REQMOD, RESPMOD\r\nOptions-TTL: " + tc.value + "\r\n\r\n"
			})
			options, err := (&ICAPClient{Timeout: time.Second}).options(context.Background(), config.ICAPServer{Address: s.ln.Addr().String()})
			if err != nil || options.ttl != tc.want {
				t.Fatalf("options = %+v, %v; want TTL %s", options, err, tc.want)
			}
		})
	}
}

func TestAVReadinessCanaryRetriesHonorCachedOptions(t *testing.T) {
	var fail atomic.Bool
	var options, uploads, downloads atomic.Int32
	s := startReadinessICAP(t, "127.0.0.1:0", func(req icapRequest) string {
		failed := fail.Load()
		if req.Method == "OPTIONS" {
			options.Add(1)
			return "ICAP/1.0 200 OK\r\nMethods: REQMOD, RESPMOD\r\nOptions-TTL: 3600\r\n\r\n"
		}
		if bytes.Equal(req.Body, []byte(avCanaryPayload)) {
			if req.Method == icapREQMOD {
				uploads.Add(1)
			} else {
				downloads.Add(1)
			}
		}
		if failed && req.Method == icapRESPMOD {
			return icapErrorReply
		}
		return healthyReadinessReply(req)
	})
	m := newTestAVManager(t, AVOptions{})
	if err := m.Apply(applyCtx(t), readinessICAPConfig(s)); err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	if res := m.Scan(context.Background(), scanObject([]byte("object"))); res.Verdict != avscan.Unscanned {
		t.Fatal(res)
	}
	// A status OPTIONS can confirm capability, never scan-path recovery.
	if status := m.Status(context.Background()); status["ready"] != false {
		t.Fatal(status)
	}
	waitFor(t, readinessTestBound, func() bool { return downloads.Load() >= 2 })
	assertAVReady(t, m, false)
	fail.Store(false)
	waitAVReady(t, m, true)
	if uploads.Load() != 1 || downloads.Load() < 3 || options.Load() != 2 {
		t.Fatalf("OPTIONS=%d, upload canaries=%d, download canaries=%d", options.Load(), uploads.Load(), downloads.Load())
	}
	m.mu.Lock()
	delay := time.Until(m.nextOptions)
	m.mu.Unlock()
	if delay > avOptionsTTLCap || delay < 20*time.Second {
		t.Fatalf("next OPTIONS in %s", delay)
	}
}

func TestAVReadinessNoSelectionPausesOptions(t *testing.T) {
	var requests atomic.Int32
	s := startReadinessICAP(t, "127.0.0.1:0", func(req icapRequest) string { requests.Add(1); return healthyReadinessReply(req) })
	m := newTestAVManager(t, AVOptions{})
	cfg := readinessICAPConfig(s)
	cfg.HTTPDownload = false
	cfg.HTTPUpload = false
	if err := m.Apply(applyCtx(t), cfg); err != nil {
		t.Fatal(err)
	}
	if m.observeDone != nil {
		t.Fatal("observer started with no selected direction")
	}
	time.Sleep(1200 * time.Millisecond)
	if requests.Load() != 1 {
		t.Fatalf("inactive selection sent %d requests", requests.Load())
	}
	cfg.HTTPDownload = true
	if err := m.Apply(applyCtx(t), cfg); err != nil {
		t.Fatal(err)
	}
	assertAVReady(t, m, true)
	if requests.Load() != 3 {
		t.Fatalf("enabling direction did not probe and scan: %d", requests.Load())
	}
}

func TestAVReadinessCachedOptionsLossBound(t *testing.T) {
	var probes atomic.Int32
	s := startReadinessICAP(t, "127.0.0.1:0", func(req icapRequest) string {
		if req.Method == "OPTIONS" {
			probes.Add(1)
			return "ICAP/1.0 200 OK\r\nMethods: REQMOD, RESPMOD\r\nOptions-TTL: 2\r\n\r\n"
		}
		return healthyReadinessReply(req)
	})
	m := newTestAVManager(t, AVOptions{})
	if err := m.Apply(applyCtx(t), readinessICAPConfig(s)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1200 * time.Millisecond)
	if probes.Load() != 1 {
		t.Fatal("OPTIONS probed before its TTL expired")
	}
	s.stop()
	waitAVReady(t, m, false)
}

func TestAVReadinessTransportAndProtocolConstraints(t *testing.T) {
	for _, tc := range []struct {
		name, reply string
		capable     bool
	}{
		{"live error", icapErrorReply, true}, {"truncated", "ICAP/1.0 500 Error\r\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var fail atomic.Bool
			s := startReadinessICAP(t, "127.0.0.1:0", func(req icapRequest) string {
				if fail.Load() && req.Method != "OPTIONS" {
					return tc.reply
				}
				return healthyReadinessReply(req)
			})
			m := newTestAVManager(t, AVOptions{})
			if err := m.Apply(applyCtx(t), readinessICAPConfig(s)); err != nil {
				t.Fatal(err)
			}
			m.stopObserver()
			fail.Store(true)
			m.Scan(context.Background(), scanObject([]byte("object")))
			assertAVReady(t, m, false)
			m.mu.Lock()
			upload, download := m.directions[avscan.Upload], m.directions[avscan.Download]
			m.mu.Unlock()
			// A protocol error is local to the failed direction; transport
			// loss invalidates scan proof for both directions of that backend.
			if upload.capable != tc.capable || download.capable != tc.capable || upload.healthy != tc.capable || download.healthy {
				t.Fatalf("upload=%+v download=%+v", upload, download)
			}
		})
	}
}

func TestAVReadinessObserverTimeoutPublishes(t *testing.T) {
	var stall atomic.Bool
	s := startReadinessICAP(t, "127.0.0.1:0", func(req icapRequest) string {
		if stall.Load() {
			return ""
		}
		return healthyReadinessReply(req)
	})
	m := newTestAVManager(t, AVOptions{})
	if err := m.Apply(applyCtx(t), readinessICAPConfig(s)); err != nil {
		t.Fatal(err)
	}
	stall.Store(true)
	waitAVReady(t, m, false)
}
