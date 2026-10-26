// SPDX-License-Identifier: Apache-2.0
package mgmtapp

import (
	"context"
	"database/sql"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/cp/config"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestReservedBootFaultPreservesRecoveryAndCandidate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.db")
	t.Setenv("CONTAIND_CONFIG_DB", path)
	t.Setenv("CONTAIND_AUDIT_DB", filepath.Join(dir, "audit.db"))
	t.Setenv("CONTAIND_USERS_DB", filepath.Join(dir, "users.db"))
	store, err := config.NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	cfg := config.DefaultConfig()
	cfg.Interfaces = []config.Interface{{Name: "custom", Device: "reserved-test", Zone: "lan", Addresses: []string{"192.0.2.2/24"}}}
	cfg.DataPlane.Enforcement = true
	f := false
	cfg.Interfaces[0].Access = config.InterfaceAccess{Mgmt: &f, HTTP: &f, HTTPS: &f, SSH: &f}
	cfg.System.Mgmt.EnableHTTP = &f
	cfg.System.Mgmt.HTTPListenAddr = ":9090"
	cfg.System.SSH.ListenAddr = ":8080"
	if err := store.Save(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := store.MutateCandidate(ctx, func(c *config.Config) error { c.Description = "staged edit survives boot"; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	r := &mgmtpath.Reservation{Device: "reserved-test", Local: netip.MustParsePrefix("10.99.99.2/24"), Sources: []netip.Addr{netip.MustParseAddr("10.99.99.10")}, Port: 8080}
	stores, running, err := initMgmtStores(zap.NewNop().Sugar(), r)
	if err != nil {
		t.Fatalf("stored conflict removed management: %v", err)
	}
	defer stores.store.Close()
	defer stores.auditStore.Close()
	defer stores.userStore.Close()
	fault, err := config.ManagementBootFaultForStore(ctx, stores.store)
	if err != nil || !strings.Contains(fault, "reserved management path") {
		t.Fatalf("fault=%q %v", fault, err)
	}
	if stores.bootEvent == nil || stores.bootEvent.Kind != "management.reservation.boot_fault" {
		t.Fatal("missing boot event")
	}
	if running.System.Mgmt.HTTPListenAddr != ":9090" || *running.System.Mgmt.EnableHTTP {
		t.Fatal("boot rewrote stored listeners")
	}
	safe := reservationSafeBootListeners(running, r)
	if err := validateReservedStartup(safe, r); err != nil {
		t.Fatal(err)
	}
	if safe.System.Mgmt.EnableHTTP == nil || !*safe.System.Mgmt.EnableHTTP || safe.System.SSH.ListenAddr == ":8080" {
		t.Fatal("unsafe boot listeners")
	}
	index := &ipInterfaceIndex{lastLoaded: time.Now(), byIP: map[string]string{"10.99.99.2": "reserved-test"}}
	handler := mgmtAccessHandler(stores.store, index, r, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	req := httptest.NewRequest("GET", "http://10.99.99.2:8080/api/v1/health", nil)
	req.RemoteAddr = "10.99.99.10:45678"
	req = req.WithContext(context.WithValue(req.Context(), localAddrKey, netip.MustParseAddrPort("10.99.99.2:8080")))
	req = req.WithContext(context.WithValue(req.Context(), localIPKey, net.ParseIP("10.99.99.2")))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("reserved recovery unavailable: %d %s", rec.Code, rec.Body)
	}
	req.RemoteAddr = "10.99.99.11:45678"
	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, req)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("negative control bypassed access gate: %d", denied.Code)
	}
	rows, err := stores.auditStore.List(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, row := range rows {
		if row.Action == "management.reservation.boot_fault" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("boot emitted %d fault events", count)
	}
	candidate, err := stores.store.LoadCandidate(ctx)
	if err != nil || candidate.Description != "staged edit survives boot" {
		t.Fatal("boot lost candidate")
	}
	candidate.Interfaces[0].Addresses = nil
	candidate.System.Mgmt = safe.System.Mgmt
	candidate.System.SSH.ListenAddr = safe.System.SSH.ListenAddr
	if err := stores.store.SaveCandidate(ctx, candidate); err != nil {
		t.Fatal(err)
	}
	if err := config.CheckManagementBootFault(ctx, stores.store); err == nil {
		t.Fatal("staging cleared boot fault")
	}
	if err := stores.store.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := config.CheckManagementBootFault(ctx, stores.store); err != nil {
		t.Fatalf("safe commit did not clear fault: %v", err)
	}
}

func TestReservedEnvironmentConflictsRemainFatal(t *testing.T) {
	r := &mgmtpath.Reservation{Device: "eth7", Local: netip.MustParsePrefix("10.99.99.2/24"), Port: 8080}
	for _, key := range []string{"CONTAIND_MGMT_ADDR", "CONTAIND_MGMT_HTTPS_ADDR", "CONTAIND_SSH_ADDR"} {
		t.Run(key, func(t *testing.T) {
			for _, k := range []string{"CONTAIND_MGMT_ADDR", "CONTAIND_MGMT_HTTPS_ADDR", "CONTAIND_SSH_ADDR"} {
				t.Setenv(k, "")
			}
			addr := ":8080"
			if key == "CONTAIND_MGMT_ADDR" {
				addr = ":9090"
			}
			t.Setenv(key, addr)
			if err := validateReservedEnvironment(r); err == nil {
				t.Fatal("deployment conflict accepted")
			}
		})
	}
}

func TestRenumberedReservedRowIsNotPinnedToStaleOwner(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Interfaces = []config.Interface{{Name: "wan", Device: "eth2", Zone: "wan", Addresses: []string{"192.0.2.2/24"}}, {Name: "lan3", Device: "eth3", Zone: "lan"}}
	r := &mgmtpath.Reservation{Device: "eth2", Local: netip.MustParsePrefix("10.99.99.2/24"), Port: 8080}
	blankDefaultInterfaceDevicesExcept(cfg, r)
	for _, iface := range cfg.Interfaces {
		if iface.Device != "" {
			t.Fatal("pinned addressed stale device after renumber")
		}
	}
}

func TestRenumberedUnaddressedReservedRowUsesSubnetAuthority(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Interfaces = []config.Interface{
		{Name: "wan", Device: "eth0", Zone: "wan"},
		{Name: "lan3", Device: "eth4", Zone: "lan"},
	}
	t.Setenv("CONTAIND_AUTO_WAN_SUBNET", "10.10.10.0/24")
	t.Setenv("CONTAIND_AUTO_LAN3_SUBNET", "10.99.99.0/24")
	r := &mgmtpath.Reservation{Device: "eth0", Local: netip.MustParsePrefix("10.99.99.2/24"), Port: 8080}
	// Both rows are unaddressed, so the old structural-only check succeeds.
	if err := config.ValidateManagementInterfaces(cfg.Interfaces, r); err != nil {
		t.Fatal(err)
	}
	blankDefaultInterfaceDevicesExcept(cfg, r)
	for _, iface := range cfg.Interfaces {
		if iface.Device != "" {
			t.Fatalf("stale physical name pinned to wrong subnet: %+v", iface)
		}
	}
	// A genuinely matching reserved row still retains its C2 binding.
	cfg.Interfaces[1].Device = r.Device
	blankDefaultInterfaceDevicesExcept(cfg, r)
	if cfg.Interfaces[1].Device != r.Device {
		t.Fatal("matching reserved owner cleared")
	}
}

func TestNonReservationBootRepairErrorWarnsAndContinues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.db")
	t.Setenv("CONTAIND_CONFIG_DB", path)
	t.Setenv("CONTAIND_AUDIT_DB", filepath.Join(dir, "audit.db"))
	t.Setenv("CONTAIND_USERS_DB", filepath.Join(dir, "users.db"))
	store, err := config.NewSQLiteStore(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.Interfaces = []config.Interface{{Name: "custom", Device: "reserved-test", Zone: "lan"}}
	cfg.DataPlane.Enforcement = true
	if err := store.Save(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER fail_repair BEFORE INSERT ON configs WHEN NEW.key IN ('running','candidate') BEGIN SELECT RAISE(ABORT,'repair test failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	r := &mgmtpath.Reservation{Device: "reserved-test", Local: netip.MustParsePrefix("10.99.99.2/24"), Port: 8080}
	core, logs := observer.New(zap.WarnLevel)
	stores, _, err := initMgmtStores(zap.New(core).Sugar(), r)
	if err != nil {
		t.Fatalf("non-reservation repair stopped management: %v", err)
	}
	defer stores.store.Close()
	defer stores.auditStore.Close()
	defer stores.userStore.Close()
	if logs.FilterMessageSnippet("repair test failure").Len() != 2 {
		t.Fatalf("repair errors not warned: %v", logs.All())
	}
	if err := config.CheckManagementBootFault(context.Background(), stores.store); err != nil {
		t.Fatalf("repair error manufactured reservation fault: %v", err)
	}
}

func TestReservedEnvironmentSSHSocketCollision(t *testing.T) {
	r := &mgmtpath.Reservation{Device: "eth7", Local: netip.MustParsePrefix("10.99.99.2/24"), Port: 8080}
	t.Setenv("CONTAIND_SSH_ADDR", "192.0.2.1:8080")
	t.Setenv("CONTAIND_MGMT_ADDR", "")
	cfg := config.DefaultConfig()
	cfg.System.Mgmt.HTTPListenAddr = "10.99.99.2:8080"
	if err := validateReservedBootEnvironment(cfg, r); err != nil {
		t.Fatalf("disjoint env socket rejected: %v", err)
	}
	cfg.System.Mgmt.HTTPListenAddr = ":8080"
	if err := validateReservedBootEnvironment(cfg, r); err == nil {
		t.Fatal("env socket collides with wildcard HTTP")
	}
}
