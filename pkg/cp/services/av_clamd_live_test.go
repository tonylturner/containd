// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/trust"
)

// eicar is the standard antivirus test file.
const eicar = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

// liveAVDir returns a world-traversable directory so a clamd that drops to
// its own account can reach the files inside.
func liveAVDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "avlive-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestLiveClamdEngine drives the real clamd and clamscan shipped in the
// engine image. Run it inside that image with CONTAIND_LIVE_CLAMAV=1; it
// needs no network: the database is one local EICAR hash signature.
func TestLiveClamdEngine(t *testing.T) {
	if os.Getenv("CONTAIND_LIVE_CLAMAV") != "1" {
		t.Skip("set CONTAIND_LIVE_CLAMAV=1 inside the engine image")
	}
	opts := DefaultAVOptions()
	if opts.ClamdPath == "" || opts.ClamscanPath == "" {
		t.Fatal("clamd and clamscan must be installed")
	}
	root := liveAVDir(t)
	opts.StateDir = filepath.Join(root, "state")
	opts.DatabaseDir = filepath.Join(root, "db")
	if err := os.MkdirAll(opts.DatabaseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// md5:size:name of the 68-byte EICAR file. clamd reports local signatures
	// with an ".UNOFFICIAL" suffix.
	if err := os.WriteFile(filepath.Join(opts.DatabaseDir, "eicar.hdb"), []byte("44d88612fea8a8f36de82e1278abb02f:68:Live.EICAR.Test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mgr := newTestAVManager(t, opts)
	cfg := clamavConfig(filepath.Join(root, "sock", "clamd.sock"))
	cfg.ClamAV.FreshclamEnabled = false
	cfg.ClamAV.CustomDefsPath = filepath.Join(root, "custom")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := mgr.Apply(ctx, cfg); err != nil {
		t.Fatalf("Apply with real clamd: %v", err)
	}
	status := mgr.Status(ctx)
	if status["ready"] != true || !strings.HasPrefix(status["db_version"].(string), "ClamAV ") {
		t.Fatalf("status = %+v", status)
	}
	t.Logf("clamd ready: %s (pid %v)", status["db_version"], status["clamav_pid"])

	if res := mgr.Scan(ctx, scanObject([]byte(eicar))); res.Verdict != "infected" || !strings.HasPrefix(res.Signature, "Live.EICAR.Test") {
		t.Fatalf("EICAR scan = %+v", res)
	}
	marker := []byte("containd live custom definition marker")
	if res := mgr.Scan(ctx, scanObject(marker)); res.Verdict != "clean" {
		t.Fatalf("clean scan = %+v", res)
	}

	// clamscan rejects a malformed database before clamd sees it.
	if _, err := mgr.UploadDefinition(ctx, "broken.ndb", strings.NewReader("not a signature")); !errors.Is(err, ErrAVInvalid) {
		t.Fatalf("malformed upload = %v", err)
	}
	// "containd live custom" in hex, as a body-anywhere ndb signature.
	sig := "Live.Custom.Marker:0:*:636f6e7461696e64206c69766520637573746f6d\n"
	def, err := mgr.UploadDefinition(ctx, "live.ndb", strings.NewReader(sig))
	if err != nil || !def.Active {
		t.Fatalf("UploadDefinition = %+v, %v", def, err)
	}
	if res := mgr.Scan(ctx, scanObject(marker)); res.Verdict != "infected" || !strings.HasPrefix(res.Signature, "Live.Custom.Marker") {
		t.Fatalf("cached marker after confirmed activation = %+v", res)
	}
	if err := mgr.DeleteDefinition(ctx, "live.ndb"); err != nil {
		t.Fatalf("DeleteDefinition: %v", err)
	}
	if res := mgr.Scan(ctx, scanObject(marker)); res.Verdict != "clean" {
		t.Fatalf("cached marker after confirmed deletion = %+v", res)
	}
}

// TestLiveFreshclamUsesDistributedTrust runs the real FreshClam against a
// local HTTPS stand-in for database.clamav.net whose certificate comes from a
// private CA. Run it inside the engine image as root with
// CONTAIND_LIVE_CLAMAV=1 and --add-host database.clamav.net:127.0.0.1.
func TestLiveFreshclamUsesDistributedTrust(t *testing.T) {
	if os.Getenv("CONTAIND_LIVE_CLAMAV") != "1" {
		t.Skip("set CONTAIND_LIVE_CLAMAV=1 inside the engine image")
	}
	opts := DefaultAVOptions()
	if opts.FreshclamPath == "" {
		t.Fatal("freshclam must be installed")
	}
	ca := newTestCA(t, "containd live mirror CA")
	var mu sync.Mutex
	var requests []string
	var handshakeErrs int
	srv := &http.Server{
		Addr:      "127.0.0.1:443",
		TLSConfig: ca.serverConfig(t, "database.clamav.net"),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			requests = append(requests, r.Method+" "+r.URL.Path)
			mu.Unlock()
			http.NotFound(w, r)
		}),
		ErrorLog: log.New(writerFunc(func(p []byte) (int, error) {
			if strings.Contains(string(p), "TLS handshake error") {
				mu.Lock()
				handshakeErrs++
				mu.Unlock()
			}
			return len(p), nil
		}), "", 0),
	}
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		t.Fatalf("listen on 443 (needs root): %v", err)
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })

	root := liveAVDir(t)
	opts.StateDir = filepath.Join(root, "state")
	opts.DatabaseDir = filepath.Join(root, "db")
	if err := os.MkdirAll(opts.DatabaseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(opts.DatabaseDir, "eicar.hdb"), []byte("44d88612fea8a8f36de82e1278abb02f:68:Live.EICAR.Test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mgr := newTestAVManager(t, opts)
	cfg := clamavConfig(filepath.Join(root, "sock", "clamd.sock"))
	cfg.ClamAV.UpdateSchedule = "24h"
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	snapshot := func() (int, int) {
		mu.Lock()
		defer mu.Unlock()
		return len(requests), handshakeErrs
	}
	waitRun := func(runs int) map[string]any {
		t.Helper()
		deadline := time.Now().Add(3 * time.Minute)
		for time.Now().Before(deadline) {
			if s := mgr.Status(ctx); s["freshclam_runs"] == runs {
				return s
			}
			time.Sleep(250 * time.Millisecond)
		}
		t.Fatalf("freshclam run %d did not finish", runs)
		return nil
	}

	// Without the private CA, FreshClam must refuse the mirror's certificate.
	if err := mgr.Apply(ctx, cfg); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	s := waitRun(1)
	reqs, hsErrs := snapshot()
	t.Logf("untrusted run: requests=%d handshake errors=%d freshclam_error=%v", reqs, hsErrs, s["freshclam_error"])
	if reqs != 0 || s["freshclam_error"] == "" {
		t.Fatalf("FreshClam reached the private mirror without its CA: requests=%d handshake errors=%d", reqs, hsErrs)
	}

	// With the distributed bundle the TLS handshake succeeds and FreshClam
	// sends its HTTP requests.
	b, err := trust.NewBundle(ca.PEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.SetTrust(ctx, b); err != nil {
		t.Fatalf("SetTrust: %v", err)
	}
	if err := mgr.RunFreshclamNow(); err != nil {
		t.Fatalf("RunFreshclamNow: %v", err)
	}
	s = waitRun(2)
	reqs, _ = snapshot()
	mu.Lock()
	t.Logf("trusted run: requests=%v freshclam_error=%v", requests, s["freshclam_error"])
	mu.Unlock()
	if reqs == 0 {
		t.Fatal("FreshClam did not trust the distributed CA bundle")
	}
	if _, ok := os.LookupEnv("CURL_CA_BUNDLE"); ok {
		t.Fatal("CURL_CA_BUNDLE leaked into the engine environment")
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }
