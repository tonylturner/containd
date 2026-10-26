// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

	if res := mgr.Scan(ctx, ScanTask{Preview: []byte(eicar)}); res.Verdict != "malware" || !strings.HasPrefix(res.Signature, "Live.EICAR.Test") {
		t.Fatalf("EICAR scan = %+v", res)
	}
	marker := []byte("containd live custom definition marker")
	if res := mgr.Scan(ctx, ScanTask{Preview: marker}); res.Verdict != "clean" {
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
	waitScan(t, mgr, marker, "malware")
	if err := mgr.DeleteDefinition(ctx, "live.ndb"); err != nil {
		t.Fatalf("DeleteDefinition: %v", err)
	}
	waitScan(t, mgr, marker, "clean")
}

// waitScan polls because clamd reloads databases in the background.
func waitScan(t *testing.T, mgr *AVManager, payload []byte, want string) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		res := mgr.Scan(context.Background(), ScanTask{Preview: payload})
		if res.Verdict == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("scan after reload = %+v, want %s", res, want)
		}
		time.Sleep(250 * time.Millisecond)
	}
}
