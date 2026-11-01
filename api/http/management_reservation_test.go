// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/netcfg"
)

func reservedAPIStore(t *testing.T) (*config.SQLiteStore, *config.Config) {
	t.Helper()
	r := &mgmtpath.Reservation{Device: "eth7", Local: netip.MustParsePrefix("10.99.99.2/24"), Sources: []netip.Addr{netip.MustParseAddr("10.99.99.10")}, Port: 8080}
	store, err := config.NewSQLiteStore(filepath.Join(t.TempDir(), "config.db"), config.WithManagementReservation(r))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	cfg := config.DefaultConfig()
	cfg.Interfaces = []config.Interface{{Name: "lan3", Device: "eth7", Zone: "lan"}}
	cfg.DataPlane.Enforcement = true
	if err := store.Save(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	return store, cfg
}

func TestManagementReservationAPIValidation(t *testing.T) {
	store, cfg := reservedAPIStore(t)
	server := NewServer(store, nil)
	cfg.Interfaces[0].AddressMode = "dhcp"
	for _, path := range []string{"/config/validate", "/config/import", "/config", "/config/candidate"} {
		rec := requestStage(t, server, "POST", path, cfg)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "reserved management path") || !strings.Contains(rec.Body.String(), "interfaces[0]") {
			t.Fatalf("%s = %d %s", path, rec.Code, rec.Body)
		}
	}
	// Reset fails before it even needs a users store. It must not wipe a
	// candidate or running when factory defaults cannot preserve the substrate.
	before, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	rec := requestStage(t, server, "POST", "/system/factory-reset", map[string]string{"confirm": "NUCLEAR"})
	after, err := store.Load(context.Background())
	if err != nil || rec.Code != http.StatusBadRequest || !reflect.DeepEqual(before, after) {
		t.Fatalf("reset preflight: %d %s, load %v", rec.Code, rec.Body, err)
	}
}

func TestManagementReservationView(t *testing.T) {
	store, _ := reservedAPIStore(t)
	health := ManagementGuardHealth(func(context.Context) (netcfg.ManagementHealth, error) {
		return netcfg.ManagementHealth{Active: true, Faults: 3, LastFault: &netcfg.ManagementFault{Reason: "source address removed", Interface: "tun0"}}, nil
	})
	server := NewServerWithEngineAndServices(store, nil, nil, nil, nil, health)
	rec := requestStage(t, server, "GET", "/system/management-reservation", nil)
	var body struct {
		Active  bool
		Device  string
		Local   string
		Sources []string
		Port    int
		Guard   netcfg.ManagementHealth
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != http.StatusOK || !body.Active || body.Device != "eth7" || body.Local != "10.99.99.2/24" || body.Port != 8080 || body.Guard.Faults != 3 || body.Guard.LastFault.Interface != "tun0" {
		t.Fatalf("reservation view = %s, %v", rec.Body, err)
	}
	rec = requestStage(t, NewServer(&mockStore{}, nil), "GET", "/system/management-reservation", nil)
	if rec.Code != http.StatusOK || rec.Body.String() != `{"active":false,"bootServiceFaults":[]}` {
		t.Fatalf("inactive view = %d %s", rec.Code, rec.Body)
	}
	rec = requestStage(t, NewServer(store, nil), "GET", "/system/management-reservation", nil)
	if !strings.Contains(rec.Body.String(), "engine guard unavailable") {
		t.Fatalf("invented healthy guard: %s", rec.Body)
	}
}

func TestReservedAutoBindKeepsExistingBinding(t *testing.T) {
	store, cfg := reservedAPIStore(t)
	cfg.Interfaces = append(cfg.Interfaces, config.Interface{Name: "wan", Zone: "wan"})
	// Discovery would prefer eth8 for lan3. The stored reserved binding wins.
	t.Setenv("CONTAIND_AUTO_LAN3_SUBNET", "192.0.2.0/24")
	state := []config.InterfaceState{
		{Name: "eth7", Index: 7, Up: true, Addrs: []string{"10.99.99.2/24"}},
		{Name: "eth8", Index: 8, Up: true, Addrs: []string{"192.0.2.2/24"}},
	}
	autoBindDefaultInterfaceDevicesReservedFromState(cfg, state, "eth8", store.ManagementReservation())
	if cfg.Interfaces[0].Device != "eth7" || cfg.Interfaces[1].Device != "eth8" {
		t.Fatalf("reserved binding moved or reused: %+v", cfg.Interfaces)
	}
}

type reservationReplayStore struct {
	*config.SQLiteStore
	snapshot *config.Config
}

func (s *reservationReplayStore) Load(context.Context) (*config.Config, error) {
	return s.snapshot, nil
}

func TestManagementReservationReplayPreflight(t *testing.T) {
	store, cfg := reservedAPIStore(t)
	cfg.DataPlane.Enforcement = false
	replay := &reservationReplayStore{SQLiteStore: store, snapshot: cfg}
	engine := &stageEngine{mockEngine: &mockEngine{}}
	services := &stageServices{}
	_, err := ApplyRunningConfig(context.Background(), replay, engine, services)
	if err == nil || !strings.Contains(err.Error(), "reserved management path") || engine.mutations != 0 || services.mutations != 0 {
		t.Fatalf("replay escaped preflight: %v engine=%d services=%d", err, engine.mutations, services.mutations)
	}
}

func TestManagementBootFaultGatesReplayAndView(t *testing.T) {
	store, _ := reservedAPIStore(t)
	ctx := context.Background()
	if err := store.SetManagementBootFault(ctx, "stored conflict"); err != nil {
		t.Fatal(err)
	}
	engine := &stageEngine{mockEngine: &mockEngine{}}
	services := &stageServices{}
	_, err := ApplyRunningConfig(ctx, store, engine, services)
	if !errors.Is(err, config.ErrManagementBootFault) || engine.mutations != 0 || services.mutations != 0 {
		t.Fatalf("boot fault replay escaped: %v", err)
	}
	rec := requestStage(t, NewServer(store, nil), "GET", "/system/management-reservation", nil)
	if !strings.Contains(rec.Body.String(), `"bootFault":"stored conflict"`) {
		t.Fatalf("fault invisible: %s", rec.Body)
	}
	if err := store.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyRunningConfig(ctx, store, engine, services); err != nil {
		t.Fatal(err)
	}
	if engine.mutations == 0 || services.mutations == 0 {
		t.Fatal("safe recovery did not resume apply")
	}
}
