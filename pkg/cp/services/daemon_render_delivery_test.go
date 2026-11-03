// SPDX-License-Identifier: Apache-2.0
package services

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestDaemonPreflightDeliveryClassification(t *testing.T) {
	t.Run("parent deadline is retryable and recovers", func(t *testing.T) {
		script, marker := sleepingPreflightScript(t)
		m := daemonPreflightDeliveryManager(t, script)
		// The deadline expires only once the preflight runs. A wall-clock
		// timeout can expire before the first exec of a new script (macOS scans
		// it), and then the test never reaches the interrupted preflight.
		ctx := startedDeadline{done: make(chan struct{})}

		type applyResult struct {
			result DeliveryResult
			err    error
		}
		done := make(chan applyResult, 1)
		go func() {
			result, err := m.ApplyDelivery(ctx, deliveryTestMeta(), config.ServicesConfig{
				DNS: config.DNSConfig{Enabled: true},
			}, nil)
			done <- applyResult{result: result, err: err}
		}()
		waitFor(t, preflightStartTimeout, func() bool {
			_, err := os.Stat(marker)
			return err == nil
		})
		close(ctx.done)
		var result DeliveryResult
		select {
		case applied := <-done:
			if applied.err != nil {
				t.Fatal(applied.err)
			}
			result = applied.result
		case <-time.After(time.Second):
			t.Fatal("delivery did not finish after parent deadline")
		}
		assertRetryablePreflightFailure(t, result)

		m.DNS.CheckConfPath = preflightScript(t, "exit 0\n")
		result, err := m.RetryDelivery(context.Background(), deliveryTestMeta())
		if err != nil {
			t.Fatal(err)
		}
		out := outcomeFor(t, result, protection.SubsystemDNS)
		if out.State != protection.DeliveryReady || out.Attempt != 2 || out.Acknowledged == nil || !result.Effective.DNS.Enabled {
			t.Fatalf("timed-out delivery did not recover: %+v", out)
		}
	})

	t.Run("parser rejection is terminal render fault", func(t *testing.T) {
		m := daemonPreflightDeliveryManager(t, preflightScript(t, "exit 1\n"))
		result, err := m.ApplyDelivery(context.Background(), deliveryTestMeta(), config.ServicesConfig{
			DNS: config.DNSConfig{Enabled: true},
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
		out := outcomeFor(t, result, protection.SubsystemDNS)
		if out.State != protection.DeliveryFailed || out.Fault == nil || out.Fault.Kind != protection.FaultRender || out.Retryable {
			t.Fatalf("wrong parser rejection classification: %+v", out)
		}
	})

	t.Run("parent cancellation is retryable", func(t *testing.T) {
		script, marker := sleepingPreflightScript(t)
		m := daemonPreflightDeliveryManager(t, script)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		type applyResult struct {
			result DeliveryResult
			err    error
		}
		done := make(chan applyResult, 1)
		go func() {
			result, err := m.ApplyDelivery(ctx, deliveryTestMeta(), config.ServicesConfig{
				DNS: config.DNSConfig{Enabled: true},
			}, nil)
			done <- applyResult{result: result, err: err}
		}()

		waitFor(t, preflightStartTimeout, func() bool {
			_, err := os.Stat(marker)
			return err == nil
		})
		cancel()
		select {
		case applied := <-done:
			if applied.err != nil {
				t.Fatal(applied.err)
			}
			assertRetryablePreflightFailure(t, applied.result)
		case <-time.After(time.Second):
			t.Fatal("delivery did not finish after parent cancellation")
		}
	})
}

// preflightStartTimeout bounds the first exec of a new preflight script; the
// script sleeps 10 s, so it is still running when the wait ends.
const preflightStartTimeout = 5 * time.Second

// startedDeadline is a parent context that reports context.DeadlineExceeded
// once done is closed.
type startedDeadline struct{ done chan struct{} }

func (startedDeadline) Deadline() (time.Time, bool) { return time.Time{}, false }
func (d startedDeadline) Done() <-chan struct{}     { return d.done }
func (startedDeadline) Value(any) any               { return nil }
func (d startedDeadline) Err() error {
	select {
	case <-d.done:
		return context.DeadlineExceeded
	default:
		return nil
	}
}

func daemonPreflightDeliveryManager(t *testing.T, script string) *Manager {
	t.Helper()
	m := NewManager(ManagerOptions{BaseDir: t.TempDir()})
	m.Syslog, m.NTP, m.Proxy, m.VPN, m.DHCP = nil, nil, nil, nil, nil
	m.DNS.Supervise = false
	m.DNS.CheckConfPath = script
	return m
}

func sleepingPreflightScript(t *testing.T) (string, string) {
	t.Helper()
	script := preflightScript(t, ": > \"$0.started\"\nexec sleep 10\n")
	return script, script + ".started"
}

func preflightScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "preflight")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertRetryablePreflightFailure(t *testing.T, result DeliveryResult) {
	t.Helper()
	out := outcomeFor(t, result, protection.SubsystemDNS)
	if out.State != protection.DeliveryFailed || !out.Retryable || out.Fault == nil || out.Fault.Kind != protection.FaultDelivery {
		t.Fatalf("wrong interrupted preflight classification: %+v", out)
	}
}
