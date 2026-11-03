// SPDX-License-Identifier: Apache-2.0
//go:build linux

package services

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/protection"
)

func TestTrafficOrphanHelper(t *testing.T) {
	if os.Getenv("CONTAIND_TEST_TRAFFIC_ORPHAN") != "1" {
		return
	}
	for {
		time.Sleep(time.Hour)
	}
}

func TestDeliveryUnknownPriorRuntimeAfterRestart(t *testing.T) {
	for _, name := range []protection.SubsystemName{protection.SubsystemOpenVPN, protection.SubsystemForwardProxy, protection.SubsystemReverseProxy} {
		t.Run(string(name), func(t *testing.T) {
			dir := t.TempDir()
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			path := trafficConfigPaths(dir, string(name))[0]
			cmd := exec.Command(exe, "-test.run=^TestTrafficOrphanHelper$", "--", "--config", path)
			cmd.Env = append(os.Environ(), "CONTAIND_TEST_TRAFFIC_ORPHAN=1")
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() { _ = cmd.Wait(); close(done) }()
			t.Cleanup(func() { _ = cmd.Process.Kill(); <-done })
			// A new manager deliberately has no child handle or previous desired input.
			m := NewManager(ManagerOptions{BaseDir: dir})
			m.Syslog, m.DNS, m.NTP, m.DHCP = nil, nil, nil, nil
			result, err := m.StopDelivery(context.Background(), deliveryTestMeta())
			if err != nil {
				t.Fatal(err)
			}
			out := outcomeFor(t, result, name)
			if out.Acknowledged == nil || out.State != protection.DeliveryOff {
				t.Fatalf("orphan stop: %+v", out)
			}
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("old traffic daemon still alive")
			}
			// A daemon worker can outlive its master and rewrite away the
			// config arguments. The inherited marker still identifies it.
			worker := exec.Command(exe, "-test.run=^TestTrafficOrphanHelper$")
			worker.Env = append(os.Environ(), "CONTAIND_TEST_TRAFFIC_ORPHAN=1", trafficOwnerTag(dir, string(name)))
			if err := worker.Start(); err != nil {
				t.Fatal(err)
			}
			workerDone := make(chan struct{})
			go func() { _ = worker.Wait(); close(workerDone) }()
			t.Cleanup(func() { _ = worker.Process.Kill(); <-workerDone })
			if _, err := m.StopDelivery(context.Background(), deliveryTestMeta()); err != nil {
				t.Fatal(err)
			}
			select {
			case <-workerDone:
			case <-time.After(2 * time.Second):
				t.Fatal("orphan tagged worker survived teardown")
			}
			// A neighboring config path is not ours, even for the same executable.
			other := exec.Command(exe, "-test.run=^TestTrafficOrphanHelper$", "--", "--config", filepath.Join(dir, "neighbor.conf"))
			other.Env = cmd.Env
			if err := other.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = other.Process.Kill(); _ = other.Wait() })
			if _, err := m.StopDelivery(context.Background(), deliveryTestMeta()); err != nil {
				t.Fatal(err)
			}
			if err := other.Process.Signal(syscall.Signal(0)); err != nil {
				t.Fatalf("unrelated daemon stopped: %v", err)
			}
		})
	}
}
