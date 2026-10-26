// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// TestFakeClamdHelper is a clamd stand-in run as a child process. It serves
// the configured LocalSocket and appends each command to its log.
func TestFakeClamdHelper(t *testing.T) {
	if os.Getenv("CONTAIND_TEST_FAKE_CLAMD") != "1" {
		return
	}
	if os.Getenv("CONTAIND_TEST_FAKE_CLAMD_NODB") == "1" {
		_, _ = os.Stderr.WriteString("LibClamAV Error: cli_loaddbdir(): No supported database files found\n")
		os.Exit(2)
	}
	var confPath string
	for _, arg := range os.Args {
		if v, ok := strings.CutPrefix(arg, "--config-file="); ok {
			confPath = v
		}
	}
	conf, err := os.ReadFile(confPath)
	if err != nil {
		os.Exit(3)
	}
	var socket string
	for _, line := range strings.Split(string(conf), "\n") {
		if v, ok := strings.CutPrefix(line, "LocalSocket "); ok {
			socket = v
		}
	}
	_ = os.Remove(socket)
	ln, err := net.Listen("unix", socket)
	if err != nil {
		os.Exit(4)
	}
	logf, err := os.OpenFile(os.Getenv("CONTAIND_TEST_FAKE_CLAMD_LOG"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		os.Exit(5)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM)
	go func() {
		<-sig
		_ = ln.Close()
		_ = os.Remove(socket)
		os.Exit(0)
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			os.Exit(0)
		}
		go serveFakeClamd(conn, func(cmd string, stream []byte) []byte {
			_, _ = logf.WriteString(cmd + "\n")
			switch cmd {
			case "PING":
				return []byte("PONG\x00")
			case "VERSION":
				return []byte("ClamAV 1.5.2/1/fake\x00")
			case "RELOAD":
				return []byte("RELOADING\x00")
			case "INSTREAM":
				if bytes.Contains(stream, []byte("EICAR")) {
					return []byte("stream: Eicar-Test-Signature FOUND\x00")
				}
				return []byte("stream: OK\x00")
			}
			return []byte("UNKNOWN COMMAND\x00")
		})
	}
}

type fakeClamAV struct {
	opts      AVOptions
	clamdLog  string
	freshLog  string
	freshExit string
	socketDir string
}

// newFakeClamAV installs fake clamd and freshclam executables.
func newFakeClamAV(t *testing.T) *fakeClamAV {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	f := &fakeClamAV{
		clamdLog:  filepath.Join(t.TempDir(), "clamd.log"),
		freshLog:  filepath.Join(t.TempDir(), "freshclam.log"),
		freshExit: filepath.Join(t.TempDir(), "freshclam.exit"),
	}
	// Unix socket paths are length-limited; keep them short.
	f.socketDir, err = os.MkdirTemp("/tmp", "avsock-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(f.socketDir) })
	t.Setenv("CONTAIND_TEST_FAKE_CLAMD", "1")
	t.Setenv("CONTAIND_TEST_FAKE_CLAMD_LOG", f.clamdLog)
	t.Setenv("CONTAIND_TEST_FAKE_EXE", exe)
	clamd := filepath.Join(bin, "clamd")
	if err := os.WriteFile(clamd, []byte("#!/bin/sh\nexec \"$CONTAIND_TEST_FAKE_EXE\" -test.run='^TestFakeClamdHelper$' -- \"$@\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	freshclam := filepath.Join(bin, "freshclam")
	script := "#!/bin/sh\necho \"run ca=${CURL_CA_BUNDLE:-none} $*\" >> '" + f.freshLog + "'\n" +
		"code=1\n[ -f '" + f.freshExit + "' ] && code=$(cat '" + f.freshExit + "')\nexit $code\n"
	if err := os.WriteFile(freshclam, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	f.opts = AVOptions{ClamdPath: clamd, FreshclamPath: freshclam}
	return f
}

func (f *fakeClamAV) socket() string { return filepath.Join(f.socketDir, "clamd.sock") }

func (f *fakeClamAV) setFreshclamExit(t *testing.T, code string) {
	t.Helper()
	if err := os.WriteFile(f.freshExit, []byte(code), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readLines(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

func countLines(path, prefix string) int {
	n := 0
	for _, l := range readLines(path) {
		if strings.HasPrefix(l, prefix) {
			n++
		}
	}
	return n
}

func clamavConfig(socket string) config.AVConfig {
	return config.AVConfig{
		Enabled:    true,
		Mode:       "clamav",
		FailPolicy: "closed",
		ClamAV:     config.ClamAVConfig{SocketPath: socket, FreshclamEnabled: true, UpdateSchedule: "1h"},
	}
}

func applyCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestAVManagerSupervisesOneClamdAndFreshclam(t *testing.T) {
	fake := newFakeClamAV(t)
	mgr := newTestAVManager(t, fake.opts)
	cfg := clamavConfig(fake.socket())
	cfg.ClamAV.CustomDefsPath = t.TempDir()

	if err := mgr.Apply(applyCtx(t), cfg); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	conf, err := os.ReadFile(filepath.Join(mgr.opts.StateDir, "clamd.conf"))
	if err != nil || !strings.Contains(string(conf), "LocalSocket "+fake.socket()+"\n") || !strings.Contains(string(conf), "DatabaseDirectory "+mgr.opts.DatabaseDir+"\n") {
		t.Fatalf("rendered clamd.conf = %q, %v", conf, err)
	}
	if strings.Contains(string(conf), "TCPSocket") {
		t.Fatal("clamd must listen on the Unix socket only")
	}
	waitFor(t, 3*time.Second, func() bool { return countLines(fake.freshLog, "run") == 1 })
	status := mgr.Status(context.Background())
	pid := status["clamav_pid"]
	if status["ready"] != true || status["db_version"] != "ClamAV 1.5.2/1/fake" || pid == 0 {
		t.Fatalf("status after apply = %+v", status)
	}
	if res := mgr.Scan(context.Background(), ScanTask{Hash: "e", Preview: []byte("xxEICARxx")}); res.Verdict != "malware" {
		t.Fatalf("scan through supervised clamd = %+v", res)
	}

	// Unrelated settings neither restart clamd nor rerun FreshClam.
	cfg.BlockTTL = 30
	cfg.TimeoutSec = 2
	if err := mgr.Apply(applyCtx(t), cfg); err != nil {
		t.Fatalf("Apply unchanged backend: %v", err)
	}
	if got := mgr.Status(context.Background())["clamav_pid"]; got != pid {
		t.Fatalf("clamd restarted for an unrelated change: %v -> %v", pid, got)
	}
	time.Sleep(100 * time.Millisecond)
	if n := countLines(fake.freshLog, "run"); n != 1 {
		t.Fatalf("freshclam ran %d times, want 1", n)
	}

	// A manual update runs on the single schedule.
	if err := mgr.RunFreshclamNow(); err != nil {
		t.Fatalf("RunFreshclamNow: %v", err)
	}
	waitFor(t, 3*time.Second, func() bool { return countLines(fake.freshLog, "run") == 2 })

	// A successful download reloads clamd and starts a new definitions generation.
	fake.setFreshclamExit(t, "0")
	gen := mgr.Status(context.Background())["definitions_generation"].(uint64)
	if err := mgr.RunFreshclamNow(); err != nil {
		t.Fatalf("RunFreshclamNow: %v", err)
	}
	waitFor(t, 3*time.Second, func() bool { return countLines(fake.clamdLog, "RELOAD") == 1 })
	waitFor(t, 3*time.Second, func() bool {
		return mgr.Status(context.Background())["definitions_generation"].(uint64) == gen+1
	})

	// A changed socket renders a new configuration and restarts clamd.
	cfg.ClamAV.SocketPath = filepath.Join(fake.socketDir, "other.sock")
	if err := mgr.Apply(applyCtx(t), cfg); err != nil {
		t.Fatalf("Apply new socket: %v", err)
	}
	if got := mgr.Status(context.Background())["clamav_pid"]; got == pid || got == 0 {
		t.Fatalf("clamd not restarted for a new socket: %v -> %v", pid, got)
	}

	// Disabling stops clamd and the schedule.
	mgr.mu.Lock()
	done := mgr.clamd.done
	mgr.mu.Unlock()
	if err := mgr.Apply(applyCtx(t), config.AVConfig{}); err != nil {
		t.Fatalf("Apply disabled: %v", err)
	}
	select {
	case <-done:
	default:
		t.Fatal("disable returned before clamd was reaped")
	}
	mgr.mu.Lock()
	scheduled := mgr.fresh.done != nil
	mgr.mu.Unlock()
	if scheduled {
		t.Fatal("freshclam schedule still running after disable")
	}
}

func TestAVManagerReportsMissingOrUnreadyBackend(t *testing.T) {
	fake := newFakeClamAV(t)
	missing := newTestAVManager(t, AVOptions{})
	if err := missing.Apply(applyCtx(t), clamavConfig(fake.socket())); err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Fatalf("Apply without clamd = %v", err)
	}

	t.Setenv("CONTAIND_TEST_FAKE_CLAMD_NODB", "1")
	nodb := newTestAVManager(t, fake.opts)
	cfg := clamavConfig(fake.socket())
	cfg.ClamAV.FreshclamEnabled = false
	err := nodb.Apply(applyCtx(t), cfg)
	if err == nil || !strings.Contains(err.Error(), "signature database is required") {
		t.Fatalf("Apply with clamd lacking a database = %v", err)
	}
	if status := nodb.Status(context.Background()); status["ready"] != false || status["last_error"] == "" {
		t.Fatalf("unready clamd reported ready: %+v", status)
	}

	cfg.ClamAV.UpdateSchedule = "0 */4 * * *"
	if err := nodb.Apply(applyCtx(t), cfg); !errors.Is(err, ErrAVInvalid) {
		t.Fatalf("cron schedule = %v, want ErrAVInvalid", err)
	}
}

func TestAVManagerCustomDefinitionsActivateAndReload(t *testing.T) {
	fake := newFakeClamAV(t)
	mgr := newTestAVManager(t, fake.opts)
	var validated []string
	mgr.validateDef = func(_ context.Context, path string) error {
		validated = append(validated, path)
		if data, _ := os.ReadFile(path); bytes.Contains(data, []byte("broken")) {
			return errors.Join(ErrAVInvalid, errors.New("malformed"))
		}
		return nil
	}
	cfg := clamavConfig(fake.socket())
	cfg.ClamAV.FreshclamEnabled = false
	cfg.ClamAV.CustomDefsPath = t.TempDir()
	if err := mgr.Apply(applyCtx(t), cfg); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	def, err := mgr.UploadDefinition(context.Background(), "local.ndb", strings.NewReader("Local.Test:0:*:4142434445"))
	if err != nil || !def.Active || def.Size == 0 {
		t.Fatalf("UploadDefinition = %+v, %v", def, err)
	}
	if len(validated) != 1 || filepath.Ext(validated[0]) != ".ndb" {
		t.Fatalf("validator saw %v", validated)
	}
	installed := filepath.Join(mgr.opts.DatabaseDir, customDefPrefix+"local.ndb")
	if data, err := os.ReadFile(installed); err != nil || string(data) != "Local.Test:0:*:4142434445" {
		t.Fatalf("activated definition = %q, %v", data, err)
	}
	if n := countLines(fake.clamdLog, "RELOAD"); n != 1 {
		t.Fatalf("clamd reloaded %d times, want 1", n)
	}
	list, err := mgr.ListDefinitions()
	if err != nil || len(list.Files) != 1 || list.Files[0] != "local.ndb" || !list.Definitions[0].Active {
		t.Fatalf("ListDefinitions = %+v, %v", list, err)
	}

	for name, body := range map[string]string{
		"../escape.ndb": "x",
		"notes.txt":     "x",
		".hidden.ndb":   "x",
		"empty.ndb":     "",
		"bad.ldb":       "broken",
	} {
		if _, err := mgr.UploadDefinition(context.Background(), name, strings.NewReader(body)); !errors.Is(err, ErrAVInvalid) {
			t.Fatalf("UploadDefinition(%q) = %v, want ErrAVInvalid", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(cfg.ClamAV.CustomDefsPath, "bad.ldb")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected definition was stored: %v", err)
	}
	big := strings.NewReader(strings.Repeat("A", MaxAVDefinitionBytes+1))
	if _, err := mgr.UploadDefinition(context.Background(), "big.hdb", big); !errors.Is(err, ErrAVInvalid) {
		t.Fatalf("oversize upload = %v", err)
	}

	if err := mgr.DeleteDefinition(context.Background(), "local.ndb"); err != nil {
		t.Fatalf("DeleteDefinition: %v", err)
	}
	if _, err := os.Stat(installed); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted definition still active: %v", err)
	}
	if n := countLines(fake.clamdLog, "RELOAD"); n != 2 {
		t.Fatalf("clamd reloaded %d times, want 2", n)
	}
	if err := mgr.DeleteDefinition(context.Background(), "local.ndb"); !errors.Is(err, ErrAVInvalid) {
		t.Fatalf("second delete = %v", err)
	}
}

func TestAVManagerStopJoinsChildren(t *testing.T) {
	fake := newFakeClamAV(t)
	mgr := NewAVManager(context.Background(), AVOptions{ClamdPath: fake.opts.ClamdPath, FreshclamPath: fake.opts.FreshclamPath, StateDir: t.TempDir(), DatabaseDir: t.TempDir()})
	if err := mgr.Apply(applyCtx(t), clamavConfig(fake.socket())); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	mgr.StartWorker()
	mgr.mu.Lock()
	done := mgr.clamd.done
	mgr.mu.Unlock()
	if err := mgr.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	select {
	case <-done:
	default:
		t.Fatal("Stop returned before clamd was reaped")
	}
	if err := mgr.Apply(applyCtx(t), clamavConfig(fake.socket())); !errors.Is(err, ErrAVStopped) {
		t.Fatalf("Apply after Stop = %v", err)
	}
	if err := mgr.Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
}
