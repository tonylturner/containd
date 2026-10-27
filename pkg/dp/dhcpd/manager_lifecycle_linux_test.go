// SPDX-License-Identifier: Apache-2.0

//go:build linux

package dhcpd

import (
	"errors"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestStaleListenerExitCannotReplaceConfiguration(t *testing.T) {
	old, current := make(chan error, 1), make(chan error, 1)
	m := &Manager{listeners: map[string]listener{"lan": {errCh: current, cfg: config.DHCPConfig{Domain: "current.example"}}}}
	m.handleListenerExit("lan", old, errors.New("old socket failed"))
	if m.listeners["lan"].errCh != current || m.listeners["lan"].cfg.Domain != "current.example" {
		t.Fatal("stale worker replaced current configuration")
	}
}

func TestRemovedListenerDoesNotRestartAfterBackoff(t *testing.T) {
	exited := make(chan error, 1)
	failed := make(chan struct{}, 1)
	m := &Manager{listeners: map[string]listener{"lan": {errCh: exited, cfg: config.DHCPConfig{Enabled: true}}},
		OnEvent: func(kind string, attrs map[string]any) {
			if kind == "service.dhcp.listener_failed" {
				failed <- struct{}{}
			}
		},
	}
	done := make(chan struct{})
	go func() { defer close(done); m.handleListenerExit("lan", exited, errors.New("socket failed")) }()
	select {
	case <-failed:
	case <-time.After(3 * time.Second):
		t.Fatal("listener did not enter backoff")
	}
	m.mu.Lock()
	delete(m.listeners, "lan")
	m.mu.Unlock()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("backoff did not finish")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.listeners) != 0 {
		t.Fatal("removed listener was restarted")
	}
}
