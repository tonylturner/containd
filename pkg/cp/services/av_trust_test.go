// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/avscan"
	"github.com/tonylturner/containd/pkg/common/trust"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func mustBundle(t *testing.T, pemText []byte) trust.Bundle {
	t.Helper()
	b, err := trust.NewBundle(pemText)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func tlsICAPConfig(t *testing.T, ca *testCA) config.AVConfig {
	t.Helper()
	addr, _ := startFakeICAP(t, ca.serverConfig(t, "localhost"), func(req icapRequest) string {
		if req.Method == "OPTIONS" {
			return "ICAP/1.0 200 OK\r\nMethods: RESPMOD\r\nEncapsulated: null-body=0\r\n\r\n"
		}
		return "ICAP/1.0 204 No Content\r\n\r\n"
	})
	_, port, _ := net.SplitHostPort(addr)
	return config.AVConfig{
		Enabled:    true,
		Mode:       "icap",
		FailPolicy: "closed",
		ICAP:       config.ICAPConfig{Servers: []config.ICAPServer{{Address: net.JoinHostPort("localhost", port), UseTLS: true}}},
	}
}

func TestAVTrustReachesICAPWithoutRestart(t *testing.T) {
	privateCA := newTestCA(t, "containd private ICAP CA")
	otherCA := newTestCA(t, "containd unrelated CA")
	cfg := tlsICAPConfig(t, privateCA)
	mgr := newTestAVManager(t, AVOptions{})
	ctx := context.Background()

	if err := mgr.Apply(ctx, cfg); err == nil {
		t.Fatal("TLS ICAP server with a private CA was trusted before the bundle arrived")
	}
	if err := mgr.SetTrust(ctx, mustBundle(t, privateCA.PEM)); err != nil {
		t.Fatalf("SetTrust: %v", err)
	}
	if err := mgr.Apply(ctx, cfg); err != nil {
		t.Fatalf("Apply after trust: %v", err)
	}
	if res := mgr.Scan(ctx, scanObject([]byte("data"))); res.Verdict != "clean" {
		t.Fatalf("Scan over TLS = %+v", res)
	}
	if status := mgr.Status(ctx); status["ready"] != true || status["trust_revision"] != trust.Revision(string(privateCA.PEM)) {
		t.Fatalf("status = %+v", status)
	}

	// Replacing the bundle takes effect on the next connection; fresh
	// content keeps the cached verdict out of the way.
	if err := mgr.SetTrust(ctx, mustBundle(t, otherCA.PEM)); err != nil {
		t.Fatalf("SetTrust(other): %v", err)
	}
	if res := mgr.Scan(ctx, scanObject([]byte("other data"))); res.Reason != avscan.ReasonScannerError || !strings.Contains(res.Detail, "certificate") {
		t.Fatalf("Scan after replacing trust = %+v", res)
	}
	if err := mgr.SetTrust(ctx, trust.Bundle{Revision: trust.NoRevision}); err != nil {
		t.Fatalf("SetTrust(clear): %v", err)
	}
	if status := mgr.Status(ctx); status["ready"] != false || status["trust_revision"] != trust.NoRevision {
		t.Fatalf("status after clear = %+v", status)
	}
}

func TestAVTrustRejectsInvalidBundles(t *testing.T) {
	ca := newTestCA(t, "containd test CA")
	mgr := newTestAVManager(t, AVOptions{})
	good := mustBundle(t, ca.PEM)
	tampered := good
	tampered.Revision = trust.Revision(good.PEM + "x")
	for name, b := range map[string]trust.Bundle{
		"tampered revision": tampered,
		"missing revision":  {PEM: good.PEM},
		"not a certificate": {PEM: "junk\n", Revision: trust.Revision("junk\n")},
	} {
		if err := mgr.SetTrust(context.Background(), b); !errors.Is(err, ErrAVInvalid) {
			t.Fatalf("%s: SetTrust = %v, want ErrAVInvalid", name, err)
		}
	}
	if got := mgr.TrustRevision(); got != trust.NoRevision {
		t.Fatalf("rejected bundle applied: %s", got)
	}
}

func TestAVTrustReachesFreshclamChildOnly(t *testing.T) {
	system := newTestCA(t, "containd stand-in system root")
	systemFile := filepath.Join(t.TempDir(), "system.pem")
	if err := os.WriteFile(systemFile, system.PEM, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", systemFile)
	private := newTestCA(t, "containd private mirror CA")
	fake := newFakeClamAV(t)
	mgr := newTestAVManager(t, fake.opts)
	finished := make(chan string, 1)
	mgr.OnEvent = func(kind string, _ map[string]any) {
		if kind == "service.av.freshclam_ok" || kind == "service.av.freshclam_failed" {
			finished <- kind
		}
	}
	awaitFreshclam := func(prefix string, count int) {
		t.Helper()
		// The child's log marks its start, not its exit. Completion is
		// emitted after the manager reaps the child and clears running.
		select {
		case kind := <-finished:
			if kind != "service.av.freshclam_ok" {
				t.Fatalf("FreshClam failed: %+v", mgr.Status(context.Background()))
			}
		case <-time.After(3 * time.Second):
			t.Fatal("FreshClam did not finish")
		}
		if got := countLines(fake.freshLog, prefix); got != count {
			t.Fatalf("FreshClam log %q: got %d runs, want %d", prefix, got, count)
		}
	}
	cfg := clamavConfig(fake.socket())
	cfg.ClamAV.CustomDefsPath = t.TempDir()
	if err := mgr.Apply(applyCtx(t), cfg); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	awaitFreshclam("run ca=none", 1)

	if err := mgr.SetTrust(context.Background(), mustBundle(t, private.PEM)); err != nil {
		t.Fatalf("SetTrust: %v", err)
	}
	bundle := filepath.Join(mgr.opts.StateDir, "ca-bundle.pem")
	if err := mgr.RunFreshclamNow(); err != nil {
		t.Fatalf("RunFreshclamNow: %v", err)
	}
	awaitFreshclam("run ca="+bundle, 1)
	data, err := os.ReadFile(bundle)
	if err != nil || !strings.Contains(string(data), strings.TrimSpace(string(system.PEM))) || !strings.Contains(string(data), strings.TrimSpace(string(private.PEM))) {
		t.Fatalf("FreshClam bundle must hold system and additional roots: %q, %v", data, err)
	}
	if v, ok := os.LookupEnv("CURL_CA_BUNDLE"); ok {
		t.Fatalf("CURL_CA_BUNDLE leaked into the engine environment: %q", v)
	}

	// Clearing removes the bundle and the variable from the next run.
	if err := mgr.SetTrust(context.Background(), trust.Bundle{Revision: trust.NoRevision}); err != nil {
		t.Fatalf("SetTrust(clear): %v", err)
	}
	if _, err := os.Stat(bundle); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cleared bundle still present: %v", err)
	}
	if err := mgr.RunFreshclamNow(); err != nil {
		t.Fatalf("RunFreshclamNow: %v", err)
	}
	awaitFreshclam("run ca=none", 2)
}
