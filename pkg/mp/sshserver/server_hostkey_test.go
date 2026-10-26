// SPDX-License-Identifier: Apache-2.0
package sshserver

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestHostKeyRotationAgeBoundaryAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host_key")
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	first, err := ensureHostKeyAt(path, 1, start)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := func(s ssh.Signer) string { return ssh.FingerprintSHA256(s.PublicKey()) }
	for _, age := range []time.Duration{0, 24*time.Hour - time.Nanosecond} {
		signer, err := ensureHostKeyAt(path, 1, start.Add(age))
		if err != nil || fingerprint(first) != fingerprint(signer) {
			t.Fatalf("premature rotation at %v: %v", age, err)
		}
	}
	rotated, err := ensureHostKeyAt(path, 1, start.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint(first) == fingerprint(rotated) {
		t.Fatal("key did not rotate at deadline")
	}
	restarted, err := ensureHostKeyAt(path, 1, start.Add(25*time.Hour))
	if err != nil || fingerprint(rotated) != fingerprint(restarted) {
		t.Fatalf("restart changed a fresh key: %v", err)
	}
	disabled, err := ensureHostKeyAt(path, 0, start.Add(100*24*time.Hour))
	if err != nil || fingerprint(rotated) != fingerprint(disabled) {
		t.Fatalf("disabled rotation changed key: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("private key permissions: %v, %v", info, err)
	}
}

func TestHostKeyInvalidAgePreservesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host_key")
	now := time.Now()
	if _, err := ensureHostKeyAt(path, 1, now); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ensureHostKeyAt(path, -1, now.Add(48*time.Hour)); err == nil {
		t.Fatal("invalid rotation setting accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("failed rotation destroyed previous key: %v", err)
	}
}

// A clock with a manually advanced wall time and ticker exercises a running
// server without waiting for a real rotation deadline.
type manualHostKeyClock struct {
	mu      sync.Mutex
	now     time.Time
	ticks   chan time.Time
	ready   chan struct{}
	stopped chan struct{}
}

func (c *manualHostKeyClock) clock() hostKeyClock {
	return hostKeyClock{
		now: func() time.Time {
			c.mu.Lock()
			defer c.mu.Unlock()
			return c.now
		},
		newTicker: func(interval time.Duration) (<-chan time.Time, func()) {
			if interval != hostKeyCheckInterval {
				panic("unexpected host key interval")
			}
			close(c.ready)
			return c.ticks, func() { close(c.stopped) }
		},
	}
}

func (c *manualHostKeyClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	now := c.now
	c.mu.Unlock()
	c.ticks <- now
}

func TestRunningHostKeyRotationPreservesSession(t *testing.T) {
	for _, shutdown := range []string{"context", "close"} {
		t.Run(shutdown, func(t *testing.T) {
			srv, _, _ := newTestSSHServer(t)
			srv.opts.ListenAddr = "127.0.0.1:0"
			srv.opts.AuditStore = nil
			srv.opts.LabMode = true
			var settingMu sync.Mutex
			days := 0
			srv.opts.HostKeyRotationDaysFunc = func(context.Context) (int, error) {
				settingMu.Lock()
				defer settingMu.Unlock()
				return days, nil
			}
			clock := &manualHostKeyClock{
				now:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				ticks: make(chan time.Time), ready: make(chan struct{}), stopped: make(chan struct{}),
			}
			srv.hostKeyClock = clock.clock()
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- srv.ListenAndServe(ctx) }()
			t.Cleanup(func() {
				cancel()
				select {
				case err := <-done:
					if err != nil {
						t.Error(err)
					}
				case <-time.After(5 * time.Second):
					t.Error("SSH server did not stop")
				}
			})
			select {
			case <-clock.ready:
			case err := <-done:
				t.Fatalf("server startup: %v", err)
			case <-time.After(5 * time.Second):
				t.Fatal("server did not start")
			}
			srv.lnMu.Lock()
			addr := srv.ln.Addr().String()
			srv.lnMu.Unlock()
			connect := func() (*ssh.Client, string) {
				t.Helper()
				var fingerprint string
				client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
					User: "containd", Auth: []ssh.AuthMethod{ssh.Password("containd")},
					Timeout: 2 * time.Second,
					HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
						fingerprint = ssh.FingerprintSHA256(key)
						return nil
					},
				})
				if err != nil {
					t.Fatal(err)
				}
				return client, fingerprint
			}
			existing, oldKey := connect()
			defer existing.Close()
			session, err := existing.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()

			// Disabled at boot; a running config update enables rotation on the next
			// check, even though no timer restart or server restart occurs.
			settingMu.Lock()
			days = 1
			settingMu.Unlock()
			clock.advance(24 * time.Hour)
			deadline := time.Now().Add(5 * time.Second)
			for {
				client, key := connect()
				_ = client.Close()
				if key != oldKey {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("new connections never received the rotated key")
				}
			}
			if err := session.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
				t.Fatalf("existing session was disrupted by rotation: %v", err)
			}
			if shutdown == "close" {
				if err := srv.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				cancel()
			}
			select {
			case <-clock.stopped:
			case <-time.After(5 * time.Second):
				t.Fatal("rotation ticker was not stopped on shutdown")
			}
		})
	}
}
