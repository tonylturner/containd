// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package pcap

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestNormalizeConfigAndHelpers(t *testing.T) {
	t.Parallel()

	cfg := normalizeConfig(config.PCAPConfig{})
	if cfg.Snaplen != 262144 || cfg.MaxSizeMB != 64 || cfg.MaxFiles != 8 || cfg.BufferMB != 4 || cfg.RotateSeconds != 300 {
		t.Fatalf("unexpected normalized config: %#v", cfg)
	}
	if cfg.FilePrefix != "capture" || cfg.Mode != "rolling" || cfg.Filter.Proto != "any" {
		t.Fatalf("unexpected normalized string defaults: %#v", cfg)
	}

	if got := uniqueStrings([]string{" eth0 ", "", "eth1", "eth0", "eth1"}); len(got) != 2 || got[0] != "eth0" || got[1] != "eth1" {
		t.Fatalf("uniqueStrings = %#v", got)
	}
	if got := sanitizeUploadName("../My Capture!.pcap"); got == "" || strings.Contains(got, "/") || strings.Contains(got, " ") || !strings.HasSuffix(strings.ToLower(got), ".pcap") {
		t.Fatalf("sanitizeUploadName = %q", got)
	}

	dir := t.TempDir()
	orig := filepath.Join(dir, "capture.pcap")
	if err := os.WriteFile(orig, []byte("pcap"), 0o644); err != nil {
		t.Fatalf("write existing file: %v", err)
	}
	if got := uniquePath(orig); got == orig || !strings.Contains(filepath.Base(got), "capture_") {
		t.Fatalf("uniquePath = %q", got)
	}
}

func TestManagerFileOperations(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	mgr := NewManager(dir)
	if mgr.dir != dir {
		t.Fatalf("manager dir = %q", mgr.dir)
	}
	if err := mgr.Configure(config.PCAPConfig{Interfaces: []string{"eth0"}, FilePrefix: "lab"}); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	if cfg := mgr.Config(); cfg.FilePrefix != "lab" || len(cfg.Interfaces) != 1 || cfg.Interfaces[0] != "eth0" {
		t.Fatalf("Config() = %#v", cfg)
	}

	item, err := mgr.Upload("../My Capture!.pcap", bytes.NewReader([]byte("pcap-data")))
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if item.SizeBytes != int64(len("pcap-data")) || !strings.HasSuffix(item.Name, ".pcap") {
		t.Fatalf("unexpected uploaded item: %#v", item)
	}
	second, err := mgr.Upload(item.Name, bytes.NewReader([]byte("pcap-data-2")))
	if err != nil {
		t.Fatalf("Upload duplicate name: %v", err)
	}
	if second.Name == item.Name {
		t.Fatalf("expected unique upload name, got %q", second.Name)
	}

	if err := mgr.Tag(item.Name, []string{"ot", "lab", "ot"}); err != nil {
		t.Fatalf("Tag: %v", err)
	}
	listed, err := mgr.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(listed) < 2 {
		t.Fatalf("expected at least 2 pcaps, got %d", len(listed))
	}
	var tagged Item
	for _, got := range listed {
		if got.Name == item.Name {
			tagged = got
			break
		}
	}
	if len(tagged.Tags) != 2 || tagged.Tags[0] != "ot" || tagged.Tags[1] != "lab" {
		t.Fatalf("unexpected tagged item: %#v", tagged)
	}

	rc, size, err := mgr.Open(item.Name)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer rc.Close()
	body, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read open body: %v", err)
	}
	if size != int64(len(body)) || string(body) != "pcap-data" {
		t.Fatalf("unexpected opened pcap: size=%d body=%q", size, string(body))
	}

	if _, err := mgr.safePath("bad.txt"); err == nil {
		t.Fatal("expected invalid safePath error")
	}
	if got := inferInterface("capture_eth7_20260313_120000.pcap"); got != "eth7" {
		t.Fatalf("inferInterface = %q", got)
	}

	if err := mgr.Delete(item.Name); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, item.Name)); !os.IsNotExist(err) {
		t.Fatalf("pcap file still exists after delete: %v", err)
	}
	if _, err := os.Stat(metaPath(filepath.Join(dir, item.Name))); !os.IsNotExist(err) {
		t.Fatalf("pcap meta still exists after delete: %v", err)
	}
}

func TestMetaHelpers(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pcapPath := filepath.Join(dir, "capture.pcap")
	meta := Meta{
		Name:      "capture.pcap",
		Interface: "eth2",
		Tags:      []string{"ot"},
		Status:    "ready",
	}
	if err := writeMeta(metaPath(pcapPath), meta); err != nil {
		t.Fatalf("writeMeta: %v", err)
	}
	got, err := readMeta(metaPath(pcapPath))
	if err != nil {
		t.Fatalf("readMeta: %v", err)
	}
	if got.Name != meta.Name || got.Interface != meta.Interface || len(got.Tags) != 1 || got.Tags[0] != "ot" {
		t.Fatalf("unexpected meta roundtrip: %#v", got)
	}
}

func TestManagerCaptureOutlivesStartRequestContext(t *testing.T) {
	t.Parallel()

	mgr := NewManager(t.TempDir())
	// Model the initiating request being canceled after Start returns. Start
	// has no request-context parameter, so the manager-owned worker context is
	// unaffected.
	requestCtx, cancelRequest := context.WithCancel(context.Background())
	defer cancelRequest()
	started := make(chan struct{})
	mgr.workerRunner = func(ctx context.Context, run *captureRun, task *captureTask) error {
		if !mgr.workerStarted(run, task) {
			return nil
		}
		close(started)
		<-ctx.Done()
		return nil
	}

	if err := mgr.Start(config.PCAPConfig{Interfaces: []string{"eth0"}}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("capture worker did not start")
	}

	cancelRequest()
	if !errors.Is(requestCtx.Err(), context.Canceled) {
		t.Fatalf("request context error = %v, want cancellation", requestCtx.Err())
	}
	if status := mgr.Status(); !status.Running {
		t.Fatalf("capture stopped with its initiating request context: %#v", status)
	}
	if err := mgr.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if status := mgr.Status(); status.Running {
		t.Fatalf("capture still running after Stop: %#v", status)
	}
}

func TestWorkerExitClearsRunningAndRecordsError(t *testing.T) {
	t.Parallel()

	mgr := NewManager(t.TempDir())
	workerStarted := make(chan struct{})
	exitWorker := make(chan struct{})
	workerErr := errors.New("capture socket failed")
	mgr.workerRunner = func(ctx context.Context, run *captureRun, task *captureTask) error {
		if !mgr.workerStarted(run, task) {
			return nil
		}
		close(workerStarted)
		<-exitWorker
		return workerErr
	}

	if err := mgr.Start(config.PCAPConfig{Interfaces: []string{"eth0"}}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	select {
	case <-workerStarted:
	case <-time.After(time.Second):
		t.Fatal("capture worker did not start")
	}
	if status := mgr.Status(); !status.Running {
		t.Fatalf("expected running worker before exit: %#v", status)
	}
	close(exitWorker)

	waitForStatus(t, mgr, func(status Status) bool {
		return !status.Running && status.LastError == workerErr.Error()
	})
	if err := mgr.Stop(); err != nil {
		t.Fatalf("Stop after natural worker exit: %v", err)
	}
}

func TestManagerStopAndRestartAreRaceFree(t *testing.T) {
	t.Parallel()

	mgr := NewManager(t.TempDir())
	var starts atomic.Int32
	started := make(chan struct{}, 2)
	mgr.workerRunner = func(ctx context.Context, run *captureRun, task *captureTask) error {
		if !mgr.workerStarted(run, task) {
			return nil
		}
		starts.Add(1)
		started <- struct{}{}
		<-ctx.Done()
		return nil
	}

	cfg := config.PCAPConfig{Interfaces: []string{"eth0"}}
	if err := mgr.Start(cfg); err != nil {
		t.Fatalf("initial Start: %v", err)
	}
	<-started

	var stops sync.WaitGroup
	stops.Add(2)
	for range 2 {
		go func() {
			defer stops.Done()
			if err := mgr.Stop(); err != nil {
				t.Errorf("concurrent Stop: %v", err)
			}
		}()
	}
	stops.Wait()

	if err := mgr.Start(cfg); err != nil {
		t.Fatalf("restart: %v", err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("restarted capture worker did not start")
	}
	if starts.Load() != 2 {
		t.Fatalf("worker starts = %d, want 2", starts.Load())
	}
	if err := mgr.Stop(); err != nil {
		t.Fatalf("Stop after restart: %v", err)
	}
}

func waitForStatus(t *testing.T, mgr *Manager, done func(Status) bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if status := mgr.Status(); done(status) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("manager did not reach expected status: %#v", mgr.Status())
}
