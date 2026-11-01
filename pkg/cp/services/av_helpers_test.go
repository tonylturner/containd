// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/avscan"
	"github.com/tonylturner/containd/pkg/cp/config"
	"go.uber.org/zap"
)

// newTestAVManager returns a manager with test paths, stopped at cleanup.
func newTestAVManager(t *testing.T, opts AVOptions) *AVManager {
	t.Helper()
	if opts.StateDir == "" {
		opts.StateDir = t.TempDir()
	}
	if opts.DatabaseDir == "" {
		opts.DatabaseDir = t.TempDir()
	}
	m := NewAVManager(context.Background(), opts)
	m.log = zap.NewNop().Sugar()
	t.Cleanup(func() {
		if err := m.Stop(); err != nil {
			t.Errorf("Stop: %v", err)
		}
	})
	return m
}

func TestAVManagerICAPApplyStatusAndFreshclamGuards(t *testing.T) {
	icapAddr, _ := startFakeICAP(t, nil, icapReply("ICAP/1.0 200 OK", "Methods: RESPMOD", "Encapsulated: null-body=0"))
	mgr := newTestAVManager(t, AVOptions{})
	var mu atomic.Value
	mgr.OnEvent = func(kind string, attrs map[string]any) { mu.Store(kind) }

	cfg := config.AVConfig{
		Enabled: true,
		Mode:    "icap",
		ICAP:    config.ICAPConfig{Servers: []config.ICAPServer{{Address: icapAddr, Service: "avscan"}}},
	}
	if err := mgr.Apply(context.Background(), cfg); err != nil {
		t.Fatalf("Apply(): %v", err)
	}
	if mu.Load() != "service.av.updated" {
		t.Fatalf("last event = %v, want service.av.updated", mu.Load())
	}
	status := mgr.Status(context.Background())
	if status["enabled"] != true || status["mode"] != "icap" || status["ready"] != true || status["clamav_custom_defs"] != DefaultCustomDefsPath {
		t.Fatalf("unexpected Status(): %+v", status)
	}
	if status["timeout"] != 5 || status["cache_ttl"] != "10m0s" {
		t.Fatalf("effective defaults not reported: %+v", status)
	}

	// An unreachable ICAP server fails the apply instead of being recorded only.
	cfg.ICAP.Servers[0].Address = "127.0.0.1:1"
	if err := mgr.Apply(context.Background(), cfg); err == nil {
		t.Fatal("Apply accepted an unreachable ICAP server")
	}
	if status := mgr.Status(context.Background()); status["ready"] != false || status["last_error"] == "" {
		t.Fatalf("unreachable server reported ready: %+v", status)
	}

	if err := (*AVManager)(nil).RunFreshclamNow(); err == nil {
		t.Fatal("expected nil manager RunFreshclamNow error")
	}
	if err := mgr.RunFreshclamNow(); !errors.Is(err, ErrAVConflict) || !strings.Contains(err.Error(), "clamav mode") {
		t.Fatalf("expected clamav mode conflict, got %v", err)
	}
	if err := mgr.Apply(context.Background(), config.AVConfig{Mode: "bogus", Enabled: true}); !errors.Is(err, ErrAVInvalid) {
		t.Fatalf("unknown mode = %v, want ErrAVInvalid", err)
	}

	for in, want := range map[string]time.Duration{"": 6 * time.Hour, " ": 6 * time.Hour, "90m": 90 * time.Minute} {
		if got, err := freshclamInterval(config.ClamAVConfig{UpdateSchedule: in}); err != nil || got != want {
			t.Fatalf("freshclamInterval(%q) = %s, %v; want %s", in, got, err, want)
		}
	}
	for _, in := range []string{"0 */4 * * *", "invalid", "0s", "-1h"} {
		if _, err := freshclamInterval(config.ClamAVConfig{UpdateSchedule: in}); !errors.Is(err, ErrAVInvalid) {
			t.Fatalf("freshclamInterval(%q) = %v, want ErrAVInvalid", in, err)
		}
	}
}

func TestAVManagerIcapAndClamAVScanPaths(t *testing.T) {
	icapAddr, _ := startFakeICAP(t, nil, icapReply("ICAP/1.0 200 OK", "X-ICAP-Status: VirusFound", "Encapsulated: null-body=0"))
	clamSock := startFakeClamd(t, nulReply("stream: Eicar-Signature FOUND"))

	mgr := newTestAVManager(t, AVOptions{})
	mgr.lastCfg = config.AVConfig{
		Enabled:    true,
		Mode:       "icap",
		FailPolicy: "open",
		ICAP:       config.ICAPConfig{Servers: []config.ICAPServer{{Address: icapAddr, Service: "avscan"}}},
	}
	if res := mgr.Scan(context.Background(), scanObject([]byte("payload"))); res.Verdict != avscan.Infected || res.Backend != "icap|"+icapAddr+"|avscan|false" {
		t.Fatalf("expected ICAP malware verdict, got %+v", res)
	}
	if res := mgr.Scan(context.Background(), uploadObject([]byte("upload payload"))); res.Verdict != avscan.Infected {
		t.Fatalf("expected ICAP malware verdict for an upload, got %+v", res)
	}

	mgr.lastCfg = config.AVConfig{
		Enabled: true,
		Mode:    "clamav",
		ClamAV:  config.ClamAVConfig{SocketPath: clamSock},
	}
	if res := mgr.Scan(context.Background(), scanObject([]byte("payload"))); res.Verdict != avscan.Infected || res.Signature != "Eicar-Signature" {
		t.Fatalf("expected ClamAV malware verdict, got %+v", res)
	}
	if status := mgr.Status(context.Background()); status["detections"] != 3 || status["count"] != 3 {
		t.Fatalf("scan counters = %+v", status)
	}
}

func TestAVManagerICAPProbeRequiresScannedMethods(t *testing.T) {
	for _, tc := range []struct {
		name, methods, errPart string
		upload, download       bool
	}{
		{"missing", "", "missing or empty Methods", true, true},
		{"empty", "Methods:", "missing or empty Methods", true, true},
		{"partial", "Methods: RESPMOD", "REQMOD", true, true},
		{"download only", "Methods: RESPMOD", "", false, true},
		{"complete", "Methods: REQMOD, RESPMOD", "", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lines := []string{"ICAP/1.0 200 OK", "Encapsulated: null-body=0"}
			if tc.methods != "" {
				lines = append(lines, tc.methods)
			}
			icapAddr, _ := startFakeICAP(t, nil, func(req icapRequest) string {
				if req.Method == "OPTIONS" {
					return icapReply(lines...)(req)
				}
				return healthyReadinessReply(req)
			})
			mgr := newTestAVManager(t, AVOptions{})
			cfg := config.AVConfig{
				Enabled: true, Mode: "icap",
				HTTPUpload: tc.upload, HTTPDownload: tc.download,
				ICAP: config.ICAPConfig{Servers: []config.ICAPServer{{Address: icapAddr}}},
			}
			err := mgr.Apply(context.Background(), cfg)
			wantReady := tc.errPart == ""
			if wantReady && err != nil || !wantReady && (err == nil || !strings.Contains(err.Error(), tc.errPart)) {
				t.Fatalf("Apply = %v, want error containing %q", err, tc.errPart)
			}
			if ready, why := mgr.Ready(); ready != wantReady || !strings.Contains(why, tc.errPart) {
				t.Fatalf("Ready = %v (%s), want %v (%s)", ready, why, wantReady, tc.errPart)
			}
			status := mgr.Status(context.Background())
			if status["ready"] != wantReady || !strings.Contains(status["ready_error"].(string), tc.errPart) {
				t.Fatalf("Status = %+v, want ready=%v (%s)", status, wantReady, tc.errPart)
			}
		})
	}
}

func TestAVManagerHonoursSizeTimeoutAndCacheScope(t *testing.T) {
	var calls atomic.Int32
	clamSock := startFakeClamd(t, func(cmd string, stream []byte) []byte {
		calls.Add(1)
		if string(stream) == "slow" {
			time.Sleep(1500 * time.Millisecond)
		}
		return []byte("stream: OK\x00")
	})
	mgr := newTestAVManager(t, AVOptions{})
	mgr.lastCfg = config.AVConfig{Enabled: true, Mode: "clamav", FailPolicy: "closed", MaxSizeBytes: 4, TimeoutSec: 1, ClamAV: config.ClamAVConfig{SocketPath: clamSock}}

	if res := mgr.Scan(context.Background(), scanObject([]byte("12345"))); res.Reason != avscan.ReasonOversized {
		t.Fatalf("oversize payload = %+v", res)
	}
	if calls.Load() != 0 {
		t.Fatalf("oversize payload reached clamd")
	}
	start := time.Now()
	if res := mgr.Scan(context.Background(), scanObject([]byte("slow"))); res.Reason != avscan.ReasonTimeout {
		t.Fatalf("slow scan = %+v", res)
	}
	if time.Since(start) > 1400*time.Millisecond {
		t.Fatalf("timeoutSec not honoured: %s", time.Since(start))
	}

	// Resetting maxSizeBytes and timeoutSec to zero restores the defaults.
	mgr.lastCfg.MaxSizeBytes = 0
	mgr.lastCfg.TimeoutSec = 0
	if res := mgr.Scan(context.Background(), scanObject([]byte("12345"))); res.Verdict != "clean" {
		t.Fatalf("unlimited scan = %+v", res)
	}
	before := calls.Load()
	if res := mgr.Scan(context.Background(), scanObject([]byte("12345"))); res.Verdict != "clean" || calls.Load() != before {
		t.Fatalf("cached scan = %+v calls %d->%d", res, before, calls.Load())
	}
	// A new definitions generation or backend must not reuse the verdict.
	mgr.defsGen++
	if mgr.Scan(context.Background(), scanObject([]byte("12345"))); calls.Load() != before+1 {
		t.Fatalf("definitions generation did not invalidate cache")
	}
	other := startFakeClamd(t, nulReply("stream: Other FOUND"))
	mgr.lastCfg.ClamAV.SocketPath = other
	if res := mgr.Scan(context.Background(), scanObject([]byte("12345"))); res.Verdict != avscan.Infected {
		t.Fatalf("backend change reused cached verdict: %+v", res)
	}
}

// scanObject is a held download with the heads an ICAP scan encapsulates
// and a real digest, so repeated scans exercise caching.
func scanObject(payload []byte) avscan.Object {
	return avscan.Object{
		Direction:    avscan.Download,
		Client:       netip.MustParseAddrPort("10.1.2.3:51000"),
		Server:       netip.MustParseAddrPort("192.0.2.10:80"),
		RequestHead:  []byte("GET /file.bin HTTP/1.1\r\nHost: files.example\r\n\r\n"),
		ResponseHead: []byte("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\n\r\n"),
		Body:         bytes.NewReader(payload),
		Size:         int64(len(payload)),
		SHA256:       fmt.Sprintf("%x", sha256.Sum256(payload)),
	}
}

// uploadObject is a held request body whose head carries the client's
// framing and content coding.
func uploadObject(payload []byte) avscan.Object {
	obj := scanObject(payload)
	obj.Direction = avscan.Upload
	obj.RequestHead = []byte("POST /upload HTTP/1.1\r\nHost: files.example\r\nContent-Length: 999\r\nContent-Encoding: gzip\r\n\r\n")
	obj.ResponseHead = nil
	return obj
}
