// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// rebindHost models a two-NIC container whose default route leaves through
// eth0, the device that also carries the LAN subnet.
func rebindHost(t *testing.T) {
	t.Helper()
	for _, logical := range defaultInterfaceOrder() {
		t.Setenv("CONTAIND_AUTO_"+strings.ToUpper(logical)+"_SUBNET", "")
		t.Setenv("CONTAIND_"+strings.ToUpper(logical)+"_SUBNET", "")
	}
	previous := discoverLocalInterfaces
	discoverLocalInterfaces = func() ([]config.InterfaceState, string, error) {
		return []config.InterfaceState{
			{Name: "lo", Index: 1, Up: true, Addrs: []string{"127.0.0.1/8"}},
			{Name: "eth0", Index: 2, Up: true, MAC: "02:42:0a:f6:49:02", Addrs: []string{"10.246.73.2/24"}},
			{Name: "eth1", Index: 3, Up: true, MAC: "02:42:0a:f5:49:02", Addrs: []string{"10.245.73.2/24"}},
		}, "eth0", nil
	}
	t.Cleanup(func() { discoverLocalInterfaces = previous })
}

// rebindStore holds the default running config with the given bindings.
func rebindStore(t *testing.T, bindings map[string]string) *config.SQLiteStore {
	t.Helper()
	store, err := config.NewSQLiteStore(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	cfg := config.DefaultConfig()
	for name, device := range bindings {
		setDevice(t, cfg, name, device)
	}
	if err := store.Save(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	return store
}

func setDevice(t *testing.T, cfg *config.Config, name, device string) {
	t.Helper()
	for i := range cfg.Interfaces {
		if cfg.Interfaces[i].Name == name {
			cfg.Interfaces[i].Device = device
			return
		}
	}
	t.Fatalf("no interface %q", name)
}

func devices(ifaces []config.Interface) map[string]string {
	out := map[string]string{}
	for _, iface := range ifaces {
		out[iface.Name] = iface.Device
	}
	return out
}

func assertBindings(t *testing.T, label string, ifaces []config.Interface, want map[string]string) {
	t.Helper()
	if got := devices(ifaces); !reflect.DeepEqual(got, want) {
		t.Fatalf("%s: bindings %v, want %v", label, got, want)
	}
}

// Moving wan off the default-route device and giving that device to lan2 is a
// valid candidate. Commit and later replays must apply it as staged.
func TestCommitAppliesStagedInterfaceRebind(t *testing.T) {
	rebindHost(t)
	// Bootstrap bound wan to the default-route device on this host.
	store := rebindStore(t, map[string]string{"wan": "eth0"})
	ctx := context.Background()
	candidate, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setDevice(t, candidate, "wan", "eth1")
	setDevice(t, candidate, "lan2", "eth0")
	want := devices(candidate.Interfaces)

	engine := &mockEngine{}
	server := NewServerWithEngine(store, nil, engine)
	if rec := requestStage(t, server, "POST", "/config/candidate", candidate); rec.Code != http.StatusOK {
		t.Fatalf("stage: %d %s", rec.Code, rec.Body)
	}
	if rec := requestStage(t, server, "POST", "/config/commit", nil); rec.Code != http.StatusOK {
		t.Fatalf("commit: %d %s", rec.Code, rec.Body)
	}
	running, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	assertBindings(t, "running", running.Interfaces, want)
	assertBindings(t, "commit apply", engine.lastIf, want)

	replay := &mockEngine{}
	if _, err := ApplyRunningConfig(ctx, store, replay, nil); err != nil {
		t.Fatalf("replay: %v", err)
	}
	assertBindings(t, "replay apply", replay.lastIf, want)
}

// Discovery still fills unbound default rows at apply time, but only with
// devices no explicit binding owns, and without persisting the result.
func TestApplyFillsOnlyUnboundDefaultInterfaces(t *testing.T) {
	rebindHost(t)
	t.Setenv("CONTAIND_AUTO_DMZ_SUBNET", "10.245.73.0/24")
	store := rebindStore(t, map[string]string{"lan2": "eth0"})
	ctx := context.Background()
	stored, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}

	engine := &mockEngine{}
	if _, err := ApplyRunningConfig(ctx, store, engine, nil); err != nil {
		t.Fatalf("apply: %v", err)
	}
	// The default route is eth0, but lan2 owns it explicitly: wan stays unbound.
	want := devices(stored.Interfaces)
	want["dmz"] = "eth1"
	assertBindings(t, "apply", engine.lastIf, want)
	after, err := store.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	assertBindings(t, "stored", after.Interfaces, devices(stored.Interfaces))
}
