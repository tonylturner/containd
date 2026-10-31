// SPDX-License-Identifier: Apache-2.0
//go:build linux

package engineapp

import (
	"context"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	"go.uber.org/zap"
)

// Test only in a disposable privileged container with iproute2:
//
//	CONTAIND_NETNS_KERNEL_TEST=1 go test -race -run TestOwnershipAddressKernel ./pkg/app/engine
func TestOwnershipAddressKernel(t *testing.T) {
	if os.Getenv("CONTAIND_NETNS_KERNEL_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("requires disposable privileged Linux container and iproute2")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := func(args ...string) {
		t.Helper()
		if out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v %s", args, err, out)
		}
	}
	if os.Getenv("CONTAIND_OWNERSHIP_ADDRESS_HELPER") == "" {
		command("netns", "add", "owner-address")
		defer command("netns", "del", "owner-address")
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		child := exec.CommandContext(ctx, "ip", "netns", "exec", "owner-address", exe, "-test.run=^TestOwnershipAddressKernel$", "-test.v")
		child.Env = append(os.Environ(), "CONTAIND_OWNERSHIP_ADDRESS_HELPER=1", "CONTAIND_ADDRESS_STATE_PATH="+filepath.Join(t.TempDir(), "addresses.json"))
		if out, err := child.CombinedOutput(); err != nil {
			t.Fatalf("namespace test: %v\n%s", err, out)
		}
		return
	}
	command("link", "add", "ownerprobe", "type", "dummy")
	command("link", "set", "ownerprobe", "up")
	command("addr", "add", "192.0.2.1/24", "dev", "ownerprobe")
	command("addr", "add", "192.0.2.2/24", "dev", "ownerprobe")
	command("-6", "addr", "add", "fe80::123/64", "dev", "ownerprobe", "nodad")
	logger := zap.NewNop().Sugar()
	owner := newOwnershipManager(logger)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/internal/interfaces", strings.NewReader(`[{"name":"ownerprobe","addresses":["192.0.2.19/24"]}]`))
	interfacesHandler(logger, owner).ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("routine apply: %d %s", rec.Code, rec.Body)
	}
	present := func(cidr string) bool {
		t.Helper()
		nic, err := net.InterfaceByName("ownerprobe")
		if err != nil {
			t.Fatal(err)
		}
		addrs, err := nic.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, a := range addrs {
			if a.String() == cidr {
				return true
			}
		}
		return false
	}
	owner.setInterfaces([]config.Interface{{Name: "ownerprobe", Addresses: []string{"192.0.2.20/24"}}})
	// The timer and event paths invoke this same bounded reconcile operation.
	owner.reconcile(ctx, "periodic")
	if owner.getLastError() != "" || present("192.0.2.19/24") || !present("192.0.2.20/24") {
		t.Fatalf("periodic convergence failed: %s", owner.getLastError())
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		owner.reconcileLoop(ctx)
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("reconcile loop leaked on cancellation")
		}
	}()
	owner.setInterfaces(nil)
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for present("192.0.2.20/24") {
		select {
		case <-deadline.C:
			t.Fatalf("empty event intent did not converge: %s", owner.getLastError())
		case <-tick.C:
		}
	}
	for _, foreign := range []string{"192.0.2.1/24", "192.0.2.2/24", "fe80::123/64"} {
		if !present(foreign) {
			t.Fatalf("routine/event/periodic apply removed foreign %s", foreign)
		}
	}
}
