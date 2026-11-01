// SPDX-License-Identifier: Apache-2.0
package config

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
)

func TestEffectiveIndependentFaultsAndPurity(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Services.DNS.UpstreamServers = []string{"bad\nforwarder"}
	cfg.Services.Proxy.Forward.Upstream = "unsupported"
	cfg.Services.VPN.WireGuard.ListenInterfaces = []string{"missing"}
	cfg.Services.VPN.OpenVPN.Mode = "bad"
	before, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	effective, faults, err := Effective(cfg, nil)
	if err != nil || len(faults) != 4 {
		t.Fatalf("projection: %v %+v", err, faults)
	}
	want := []string{ServiceDNS, ServiceOpenVPN, ServiceProxy, ServiceWireGuard}
	for i, f := range faults {
		if f.Service != want[i] {
			t.Fatalf("fault order: %+v", faults)
		}
	}
	if err := effective.Validate(); err != nil {
		t.Fatal(err)
	}
	effective.Interfaces[0].Name = "detached"
	effective.IDS.Rules[0].Labels["category"] = "detached"
	after, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("projection mutated desired state")
	}
	// A broken service must not mask later enforcement-policy validation.
	cfg.Services.AV.Scan.DownloadMode = "bad"
	if effective, faults, err := Effective(cfg, nil); err == nil || effective != nil || len(faults) != 4 {
		t.Fatalf("masked scan policy error: %v %+v", err, faults)
	}
	cfg.Services.AV.Scan = ScanSelection{}
	cfg.Services.DHCP.Enabled = true
	cfg.Services.DHCP.ListenIfaces = []string{"bad\niface"}
	effective, faults, err = Effective(cfg, nil)
	if err != nil || len(faults) != 5 || faults[0].Service != ServiceDHCP || effective.Services.DHCP.Enabled {
		t.Fatalf("DHCP listen fault was not quarantined independently: %v %+v", err, faults)
	}
}

func TestEffectiveReservedListenerIsServiceFault(t *testing.T) {
	r := &mgmtpath.Reservation{Device: "mgmt0", Local: netip.MustParsePrefix("10.99.99.2/24"), Port: 8080}
	cfg := DefaultConfig()
	cfg.DataPlane.Enforcement = true
	cfg.Interfaces = []Interface{{Name: "management", Device: r.Device, Zone: "lan"}}
	cfg.Services.Proxy.Forward.Enabled = true
	cfg.Services.Proxy.Forward.ListenPort = 8080
	cfg.Services.DNS.Enabled = true
	cfg.Services.DNS.ListenPort = 8080
	effective, faults, err := Effective(cfg, r)
	if err != nil || len(faults) != 2 || effective.Services.Proxy.Forward.Enabled || effective.Services.DNS.Enabled {
		t.Fatalf("listener collision was not quarantined: %v %+v", err, faults)
	}
	cfg.Interfaces[0].Addresses = []string{"10.99.99.2/24"}
	if _, _, err := Effective(cfg, r); err == nil {
		t.Fatal("core reservation conflict was ignored")
	}
}

func TestCheckWriteCarriedFaults(t *testing.T) {
	base := DefaultConfig()
	base.Services.Proxy.Forward.Upstream = "legacy"
	next := cloneConfigForPersist(base)
	next.Description = "firewall repair"
	if err := CheckWrite(base, next, nil); err != nil {
		t.Fatal(err)
	}
	if err := CheckWrite(nil, next, nil); err == nil {
		t.Fatal("strict defaults accepted a fault")
	}
	next.Services.Proxy.Forward.Upstream = "different invalid value"
	if err := CheckWrite(base, next, nil); err == nil {
		t.Fatal("changed invalid service accepted")
	}
	next.Services.Proxy = ProxyConfig{}
	if err := CheckWrite(base, next, nil); err != nil {
		t.Fatal("clearing a service must work", err)
	}
	next.Services.DNS.CacheSizeMB = -1
	if err := CheckWrite(base, next, nil); err == nil {
		t.Fatal("new service fault accepted")
	}
}

func installStoredFault(t *testing.T, s *SQLiteStore, cfg *Config) {
	t.Helper()
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback() //nolint:errcheck
	if err := writeConfigTx(context.Background(), tx, configKeyRunning, cfg); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestStoredFaultPromotionRestoreConfirmAndExpiry(t *testing.T) {
	s := candidateStore(t)
	ctx := context.Background()
	cfg, err := s.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Services.Proxy.Forward.Upstream = "legacy"
	installStoredFault(t, s, cfg)
	if err := testMutateCandidate(s, ctx, func(c *Config) error { c.Description = "repair"; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := testCommitConfirmed(s, ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := testConfirmCommit(s, ctx); err != nil {
		t.Fatal(err)
	}
	if err := testMutateCandidate(s, ctx, func(c *Config) error { c.Services.Proxy = ProxyConfig{}; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := testCommitConfirmed(s, ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(pendingCommit{DeadlineUnix: time.Now().Add(-time.Hour).UnixNano()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE configs SET data=? WHERE key=?`, string(data), configKeyPending); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	applied, err := s.timedRollbackLocked(ctx)
	s.mu.Unlock()
	if err != nil || !applied {
		t.Fatalf("service fault refused expiry: %v", err)
	}
	running, err := s.Load(ctx)
	if err != nil || running.Services.Proxy.Forward.Upstream != "legacy" {
		t.Fatalf("restoration persisted projection: %v %+v", err, running)
	}
	if err := testMutateCandidate(s, ctx, func(c *Config) error { c.Description = "failed change"; return nil }); err != nil {
		t.Fatal(err)
	}
	attempts := 0
	err = testApplyChange(s, ctx, ChangeCommit, 0, func(_ context.Context, _, next *Config) error {
		attempts++
		_, faults, err := Effective(next, nil)
		if err != nil || len(faults) != 1 {
			t.Fatalf("callback did not project stored fault: %v %+v", err, faults)
		}
		if attempts == 1 {
			return errors.New("ruleset failed")
		}
		return nil
	})
	var failure *ApplyError
	if !errors.As(err, &failure) || failure.ReapplyError != nil || attempts != 2 {
		t.Fatalf("compensation: %v attempts=%d", err, attempts)
	}
}

func TestRepairPreservesServicesAndAllowsNewReferenceFault(t *testing.T) {
	s := candidateStore(t)
	ctx := context.Background()
	cfg, _ := s.Load(ctx)
	cfg.Interfaces[0].Device = "oldnic"
	cfg.Services.VPN.WireGuard.ListenInterfaces = []string{"oldnic"}
	if err := s.Save(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	got, err := Repair(ctx, s, func(c *Config) error { c.Interfaces[0].Device = "newnic"; return nil })
	if err != nil || !reflect.DeepEqual(got.Services, cfg.Services) {
		t.Fatalf("repair lost service content: %v", err)
	}
	_, faults, err := Effective(got, nil)
	if err != nil || len(faults) != 1 || faults[0].Service != ServiceWireGuard {
		t.Fatalf("reference fault not recomputed: %v %+v", err, faults)
	}
	if _, err := Repair(ctx, s, func(c *Config) error { c.Services.DNS.UpstreamServers = []string{}; return nil }); err == nil {
		t.Fatal("repair changed a nil service collection to empty")
	}
	if _, err := Repair(ctx, s, func(c *Config) error { c.Services.VPN = VPNConfig{}; return nil }); err == nil {
		t.Fatal("repair edited services")
	}
}

func TestStoredFaultExpiredAtOpen(t *testing.T) {
	s := candidateStore(t)
	ctx := context.Background()
	cfg, err := s.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Services.Proxy.Forward.Upstream = "legacy"
	installStoredFault(t, s, cfg)
	if err := testMutateCandidate(s, ctx, func(c *Config) error { c.Services.Proxy = ProxyConfig{}; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := testCommitConfirmed(s, ctx, time.Hour); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(pendingCommit{DeadlineUnix: time.Now().Add(-time.Hour).UnixNano()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE configs SET data=? WHERE key=?`, string(data), configKeyPending); err != nil {
		t.Fatal(err)
	}
	s = reopenSnapshotStore(t, s)
	running, err := s.Load(ctx)
	if err != nil || running.Services.Proxy.Forward.Upstream != "legacy" {
		t.Fatalf("at-open expiry refused service-only fault: %v %+v", err, running)
	}
	if _, err := s.loadPending(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expiry retained pending commit: %v", err)
	}
}

func TestStoredServiceBootFaultRecord(t *testing.T) {
	s := candidateStore(t)
	ctx := context.Background()
	faults := []ServiceFault{{Service: ServiceProxy, Kind: "config", Message: "bad listener"}}
	if err := s.SetServiceBootFaults(ctx, faults); err != nil {
		t.Fatal(err)
	}
	s = reopenSnapshotStore(t, s)
	got, err := ServiceBootFaultsForStore(ctx, s)
	if err != nil || !reflect.DeepEqual(got, faults) {
		t.Fatalf("boot fault record lost across reopen: %v %+v", err, got)
	}
	if err := CheckManagementBootFault(ctx, s); err != nil {
		t.Fatal("service boot record activated management recovery", err)
	}
	if err := s.SetServiceBootFaults(ctx, []ServiceFault{}); err != nil {
		t.Fatal(err)
	}
	if got, err := ServiceBootFaultsForStore(ctx, s); err != nil || got == nil || len(got) != 0 {
		t.Fatalf("healthy boot retained service faults: %v %+v", err, got)
	}
}
