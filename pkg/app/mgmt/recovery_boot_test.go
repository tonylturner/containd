// SPDX-License-Identifier: Apache-2.0
package mgmtapp

import (
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	engineapi "github.com/tonylturner/containd/api/engine"
	"github.com/tonylturner/containd/pkg/cp/compile"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"go.uber.org/zap"
)

// setStoredRules replaces the running rules behind the store's validation,
// as an upgrade that tightens validation leaves an existing store.
func setStoredRules(t *testing.T, path string, firewallRules []config.Rule) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var raw string
	if err := db.QueryRow(`SELECT data FROM configs WHERE key = 'running'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatal(err)
	}
	firewall, ok := doc["firewall"].(map[string]any)
	if !ok {
		t.Fatalf("stored config has no firewall object: %s", raw)
	}
	firewall["rules"] = firewallRules
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE configs SET data = ? WHERE key = 'running'`, string(body)); err != nil {
		t.Fatal(err)
	}
}

type recordedEngineCall struct {
	path     string
	dp       config.DataPlaneConfig
	snapshot rules.Snapshot
}

// recordingEngine records each request only after reading its body, so a
// test that stops on a recorded call never cancels a request mid-body.
func recordingEngine(t *testing.T) (*httptest.Server, <-chan recordedEngineCall) {
	t.Helper()
	calls := make(chan recordedEngineCall, 64)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := recordedEngineCall{path: r.URL.Path}
		var err error
		switch r.URL.Path {
		case "/internal/config":
			err = json.NewDecoder(r.Body).Decode(&call.dp)
		case "/internal/apply_rules":
			err = json.NewDecoder(r.Body).Decode(&call.snapshot)
		}
		if err != nil {
			t.Error(err)
		}
		calls <- call
		if r.URL.Path == "/health" {
			_, _ = w.Write([]byte(`{"bootId":"boot-1","iec104Enforcement":{"healthy":true}}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	return srv, calls
}

// nextRuleset returns the next ruleset push and the paths pushed before it.
func nextRuleset(t *testing.T, calls <-chan recordedEngineCall) (recordedEngineCall, []recordedEngineCall) {
	t.Helper()
	var before []recordedEngineCall
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		select {
		case call := <-calls:
			if call.path == "/internal/apply_rules" {
				return call, before
			}
			before = append(before, call)
		case <-timer.C:
			t.Fatalf("no ruleset pushed; saw %v", before)
		}
	}
}

func TestInvalidStoredConfigBootsIntoRecovery(t *testing.T) {
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
	f := false
	cfg := config.DefaultConfig()
	cfg.Interfaces = []config.Interface{
		{Name: "mgmt0", Device: "mgmtnic", Zone: "mgmt"},
		{Name: "wan0", Device: "wannic", Zone: "wan", Access: config.InterfaceAccess{Mgmt: &f}},
	}
	cfg.DataPlane.Enforcement = true
	if err := store.Save(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	// Semantic enforce with no queue: valid before the inline-path rule.
	enforced := config.Rule{
		ID: "modbus-enforce", Action: config.ActionAllow,
		Protocols: []config.Protocol{{Name: "tcp", Port: "502"}},
		ICS:       config.ICSPredicate{Protocol: "modbus", Mode: "enforce"},
	}
	setStoredRules(t, path, []config.Rule{enforced})

	stores, running, err := initMgmtStores(zap.NewNop().Sugar(), nil)
	if err != nil {
		t.Fatalf("invalid stored config stopped management: %v", err)
	}
	defer stores.store.Close()
	defer stores.auditStore.Close()
	defer stores.userStore.Close()
	fault, err := config.ManagementBootFaultForStore(ctx, stores.store)
	if err != nil || !strings.Contains(fault, "rule modbus-enforce: modbus enforce needs an inline path") {
		t.Fatalf("fault=%q %v", fault, err)
	}
	if stores.bootEvent == nil || stores.bootEvent.Kind != "management.recovery.boot_fault" {
		t.Fatalf("boot event = %+v", stores.bootEvent)
	}
	rows, err := stores.auditStore.List(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	audited := 0
	for _, row := range rows {
		if row.Action == "management.recovery.boot_fault" {
			audited++
		}
	}
	if audited != 1 {
		t.Fatalf("boot audited %d faults", audited)
	}
	if len(running.Firewall.Rules) != 1 || running.Firewall.Rules[0].ICS.Mode != "enforce" {
		t.Fatalf("boot rewrote the stored rules: %+v", running.Firewall.Rules)
	}

	// Management stays reachable exactly where stored access grants it.
	index := &ipInterfaceIndex{lastLoaded: time.Now(), byIP: map[string]string{"192.0.2.2": "mgmtnic", "198.51.100.2": "wannic"}}
	handler := mgmtAccessHandler(stores.store, index, nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	for local, want := range map[string]int{"192.0.2.2": http.StatusOK, "198.51.100.2": http.StatusForbidden} {
		req := httptest.NewRequest("GET", "http://"+local+":8080/api/v1/health", nil)
		req.RemoteAddr = "192.0.2.10:45678"
		req = req.WithContext(context.WithValue(req.Context(), localAddrKey, netip.MustParseAddrPort(local+":8080")))
		req = req.WithContext(context.WithValue(req.Context(), localIPKey, net.ParseIP(local)))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("management via %s = %d, want %d", local, rec.Code, want)
		}
	}

	srv, calls := recordingEngine(t)
	stop := startEngineSync(ctx, zap.NewNop().Sugar(), stores.store, engineapi.NewHTTPClient(srv.URL), nil)
	defer stop()
	recovery, before := nextRuleset(t, calls)
	var paths []string
	var dp *config.DataPlaneConfig
	for _, call := range before {
		paths = append(paths, call.path)
		if call.path == "/internal/config" {
			dp = &call.dp
		}
	}
	if !reflect.DeepEqual(paths, []string{"/health", "/internal/config"}) {
		t.Fatalf("recovery pushed stored runtime state: %v", paths)
	}
	if dp == nil || !dp.Enforcement || len(dp.CaptureInterfaces) != 0 || dp.DPIEnabled || dp.NFQueueGroup != 0 {
		t.Fatalf("recovery dataplane = %+v", dp)
	}
	snap := recovery.snapshot
	if snap.Version != config.ManagementRecoveryVersion || snap.Default != rules.ActionDeny ||
		len(snap.Firewall) != 0 || snap.NAT.Enabled || len(snap.ZoneIfaces) != 0 {
		t.Fatalf("recovery ruleset admits stored transit: %+v", snap)
	}
	// The stored listeners, and the default ones management falls back to,
	// with exactly the stored interface access.
	stored := compile.ManagementLocalInput(running)
	access := map[string]rules.LocalServiceRule{}
	for _, rule := range stored {
		access[rule.ID] = rule
	}
	for _, want := range stored {
		if !slices.ContainsFunc(snap.LocalInput, func(have rules.LocalServiceRule) bool { return reflect.DeepEqual(have, want) }) {
			t.Fatalf("recovery management input = %+v, want stored access %+v", snap.LocalInput, stored)
		}
	}
	for _, have := range snap.LocalInput {
		if want, ok := access[have.ID]; ok && (!reflect.DeepEqual(have.Ifaces, want.Ifaces) || !reflect.DeepEqual(have.DeniedIfaces, want.DeniedIfaces)) {
			t.Fatalf("recovery management input %+v widens stored access %+v", have, want)
		}
	}
	var http8080 *rules.LocalServiceRule
	for i := range snap.LocalInput {
		if snap.LocalInput[i].Port == 8080 {
			http8080 = &snap.LocalInput[i]
		}
	}
	if http8080 == nil || !reflect.DeepEqual(http8080.Ifaces, []string{"mgmtnic"}) || !reflect.DeepEqual(http8080.DeniedIfaces, []string{"wannic"}) {
		t.Fatalf("recovery HTTP management input = %+v", http8080)
	}

	// A fixed commit leaves recovery and replays the stored policy.
	candidateSnapshot1, err := stores.store.ReadSnapshot(ctx, config.SnapshotCandidate, true)
	candidate := candidateSnapshot1.Candidate
	if err != nil {
		t.Fatal(err)
	}
	candidate.Firewall.Rules[0].ICS.Mode = "monitor"
	if err := testSaveCandidate(stores.store, ctx, candidate); err != nil {
		t.Fatal(err)
	}
	if err := config.CheckManagementBootFault(ctx, stores.store); err == nil {
		t.Fatal("staging cleared the boot fault")
	}
	if err := testCommit(stores.store, ctx); err != nil {
		t.Fatal(err)
	}
	if err := config.CheckManagementBootFault(ctx, stores.store); err != nil {
		t.Fatalf("valid commit kept recovery: %v", err)
	}
	normal, _ := nextRuleset(t, calls)
	if normal.snapshot.Version == config.ManagementRecoveryVersion || len(normal.snapshot.Firewall) != 1 || normal.snapshot.Firewall[0].ID != "modbus-enforce" {
		t.Fatalf("commit did not replace recovery: %+v", normal.snapshot)
	}
}

func TestBootWithoutReservationClearsHistoricalFault(t *testing.T) {
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
	cfg.Interfaces = []config.Interface{{Name: "custom", Device: "custom0", Zone: "lan"}}
	if err := store.Save(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	// Left by an earlier boot whose reservation has since been removed.
	if err := store.SetManagementBootFault(ctx, "historical reservation conflict"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	stores, _, err := initMgmtStores(zap.NewNop().Sugar(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stores.store.Close()
	defer stores.auditStore.Close()
	defer stores.userStore.Close()
	if err := config.CheckManagementBootFault(ctx, stores.store); err != nil || stores.bootEvent != nil {
		t.Fatalf("valid config without reservation stayed in recovery: %v event=%v", err, stores.bootEvent)
	}
}

func TestUnsupportedICSAddressesBootIntoRecovery(t *testing.T) {
	for _, tc := range []struct {
		protocol string
		port     string
	}{
		{protocol: "dnp3", port: "20000"},
		{protocol: "cip", port: "44818"},
	} {
		t.Run(tc.protocol, func(t *testing.T) {
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
			f := false
			cfg := config.DefaultConfig()
			cfg.Interfaces = []config.Interface{
				{Name: "mgmt0", Device: "mgmtnic", Zone: "mgmt"},
				{Name: "wan0", Device: "wannic", Zone: "wan", Access: config.InterfaceAccess{Mgmt: &f}},
			}
			cfg.DataPlane.Enforcement = true
			cfg.DataPlane.DPIEnabled = true
			cfg.DataPlane.NFQueueGroup = 100
			if err := store.Save(ctx, cfg); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}

			const ruleID = "unsupported-address"
			addresses := []string{"10-20"}
			setStoredRules(t, path, []config.Rule{{
				ID: ruleID, Action: config.ActionAllow,
				Protocols: []config.Protocol{{Name: "tcp", Port: tc.port}},
				ICS:       config.ICSPredicate{Protocol: tc.protocol, Addresses: addresses},
			}})

			stores, running, err := initMgmtStores(zap.NewNop().Sugar(), nil)
			if err != nil {
				t.Fatalf("invalid stored config stopped management: %v", err)
			}
			defer stores.store.Close()
			defer stores.auditStore.Close()
			defer stores.userStore.Close()

			reason := "addresses is not supported for protocol cip; use target selectors"
			if tc.protocol == "dnp3" {
				reason = "addresses requires non-empty groups for protocol dnp3"
			}
			wantFault := "rule " + ruleID + " ics " + reason
			fault, err := config.ManagementBootFaultForStore(ctx, stores.store)
			if err != nil || !strings.Contains(fault, wantFault) {
				t.Fatalf("boot fault = %q, want %q (err=%v)", fault, wantFault, err)
			}
			var eventFault string
			if stores.bootEvent != nil {
				eventFault, _ = stores.bootEvent.Attributes["error"].(string)
			}
			if stores.bootEvent == nil || stores.bootEvent.Kind != "management.recovery.boot_fault" ||
				!strings.Contains(eventFault, wantFault) {
				t.Fatalf("boot event = %+v, want recovery fault %q", stores.bootEvent, wantFault)
			}
			rows, err := stores.auditStore.List(ctx, 100)
			if err != nil {
				t.Fatal(err)
			}
			audited := 0
			for _, row := range rows {
				if row.Action == "management.recovery.boot_fault" {
					audited++
				}
			}
			if audited != 1 {
				t.Fatalf("boot audited %d recovery faults, want 1", audited)
			}
			if len(running.Firewall.Rules) != 1 ||
				running.Firewall.Rules[0].ID != ruleID ||
				running.Firewall.Rules[0].ICS.Protocol != tc.protocol ||
				!reflect.DeepEqual(running.Firewall.Rules[0].ICS.Addresses, addresses) {
				t.Fatalf("boot dropped or rewrote the stored rule: %+v", running.Firewall.Rules)
			}

			srv, calls := recordingEngine(t)
			stop := startEngineSync(ctx, zap.NewNop().Sugar(), stores.store, engineapi.NewHTTPClient(srv.URL), nil)
			defer stop()
			recovery, before := nextRuleset(t, calls)
			var paths []string
			var dp *config.DataPlaneConfig
			for _, call := range before {
				paths = append(paths, call.path)
				if call.path == "/internal/config" {
					dp = &call.dp
				}
			}
			if !reflect.DeepEqual(paths, []string{"/health", "/internal/config"}) {
				t.Fatalf("recovery replayed stored runtime state: %v", paths)
			}
			if dp == nil || !dp.Enforcement || len(dp.CaptureInterfaces) != 0 || dp.DPIEnabled || dp.NFQueueGroup != 0 {
				t.Fatalf("recovery dataplane = %+v", dp)
			}
			snap := recovery.snapshot
			if snap.Version != config.ManagementRecoveryVersion || snap.Default != rules.ActionDeny ||
				len(snap.Firewall) != 0 || snap.NAT.Enabled || len(snap.ZoneIfaces) != 0 {
				t.Fatalf("recovery ruleset admits stored transit: %+v", snap)
			}
		})
	}
}
