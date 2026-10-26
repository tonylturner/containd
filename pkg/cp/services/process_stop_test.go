// SPDX-License-Identifier: Apache-2.0
package services

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestManagedDaemonHelper(t *testing.T) {
	if os.Getenv("CONTAIND_TEST_DAEMON") != "1" {
		return
	}
	signal.Ignore(syscall.SIGTERM)
	if err := os.WriteFile(os.Getenv("CONTAIND_TEST_DAEMON_READY"), []byte("ready"), 0o600); err != nil {
		os.Exit(2)
	}
	for {
		time.Sleep(time.Hour)
	}
}

func managedDaemonScript(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONTAIND_TEST_DAEMON", "1")
	t.Setenv("CONTAIND_TEST_DAEMON_EXE", exe)
	t.Setenv("CONTAIND_TEST_DAEMON_READY", filepath.Join(t.TempDir(), "ready"))
	script := filepath.Join(t.TempDir(), "daemon")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nif [ \"$1\" = '-t' ]; then exit 0; fi\nexec \"$CONTAIND_TEST_DAEMON_EXE\" -test.run='^TestManagedDaemonHelper$'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return script
}

func waitDaemonReady(t *testing.T) {
	t.Helper()
	waitFor(t, 3*time.Second, func() bool {
		_, err := os.Stat(os.Getenv("CONTAIND_TEST_DAEMON_READY"))
		return err == nil
	})
}

func assertReaped(t *testing.T, done <-chan struct{}, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	default:
		t.Fatal("disable returned before daemon was reaped")
	}
}

func TestDNSDisableReapsUnresponsiveDaemon(t *testing.T) {
	m := NewDNSManager(t.TempDir())
	m.UnboundPath = managedDaemonScript(t)
	m.CheckConfPath = ""
	if err := m.startOrReload("unused"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.stopLocked() })
	waitDaemonReady(t)
	done := m.done
	// Disable must not require a still-installed executable.
	m.UnboundPath = ""
	assertReaped(t, done, m.Apply(context.Background(), config.DNSConfig{}))
}

func TestProxyDisableReapsUnresponsiveDaemons(t *testing.T) {
	for _, daemon := range []string{"envoy", "nginx"} {
		t.Run(daemon, func(t *testing.T) {
			script := managedDaemonScript(t)
			m := NewProxyManager(ProxyOptions{BaseDir: t.TempDir(), Supervise: true, EnvoyPath: script, NginxPath: script})
			t.Cleanup(func() { _ = m.stopEnvoy(); _ = m.stopNginx() })
			var done <-chan struct{}
			if daemon == "envoy" {
				if err := os.WriteFile(filepath.Join(m.BaseDir, "envoy-forward.yaml"), []byte("config"), 0o600); err != nil {
					t.Fatal(err)
				}
				m.startOrRestartEnvoy(context.Background())
				done = m.envoyDone
			} else {
				if err := os.WriteFile(filepath.Join(m.BaseDir, "nginx-reverse.conf"), []byte("config"), 0o600); err != nil {
					t.Fatal(err)
				}
				m.startOrRestartNginx(context.Background())
				done = m.nginxDone
			}
			waitDaemonReady(t)
			assertReaped(t, done, m.Apply(context.Background(), config.ProxyConfig{}))
		})
	}
}

func TestAVDisableReapsUnresponsiveClamd(t *testing.T) {
	m := newTestAVManager(t, AVOptions{ClamdPath: managedDaemonScript(t)})
	if err := m.startClamd("unused"); err != nil {
		t.Fatal(err)
	}
	waitDaemonReady(t)
	m.mu.Lock()
	done := m.clamd.done
	m.mu.Unlock()
	assertReaped(t, done, m.Apply(context.Background(), config.AVConfig{}))
}
