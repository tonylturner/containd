// SPDX-License-Identifier: Apache-2.0
package mgmtapp

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/cp/config"
	"go.uber.org/zap"
)

type bootFaultRecordingStore struct {
	config.Store
	calls int
	fault string
}

func (s *bootFaultRecordingStore) SetManagementBootFault(_ context.Context, fault string) error {
	s.calls++
	s.fault = fault
	return nil
}

func TestBootDecisionWithoutReservationClearsValidFault(t *testing.T) {
	store := &bootFaultRecordingStore{fault: "historical fault"}
	cfg := config.DefaultConfig()
	event, err := recordBootDecision(zap.NewNop().Sugar(), mgmtStores{store: store}, cfg, nil)
	if err != nil || event != nil || store.calls != 1 || store.fault != "" {
		t.Fatalf("valid boot kept a fault: event=%v err=%v calls=%d fault=%q", event, err, store.calls, store.fault)
	}
}

func TestBootDecisionStoreCapability(t *testing.T) {
	r := &mgmtpath.Reservation{
		Device: "fixture", Local: netip.MustParsePrefix("10.99.99.2/24"), Port: 8080,
	}
	cfg := config.DefaultConfig()
	cfg.Interfaces = []config.Interface{{Name: "custom", Device: r.Device, Zone: "lan"}}
	cfg.DataPlane.Enforcement = true
	store := &bootFaultRecordingStore{fault: "old fault"}
	event, err := recordBootDecision(zap.NewNop().Sugar(), mgmtStores{store: store}, cfg, r)
	if err != nil || event != nil || store.calls != 1 || store.fault != "" {
		t.Fatalf("non-SQLite recorder rejected: event=%v err=%v calls=%d fault=%q", event, err, store.calls, store.fault)
	}
	unsupported := &struct{ config.Store }{}
	_, err = recordBootDecision(zap.NewNop().Sugar(), mgmtStores{store: unsupported}, cfg, r)
	if err == nil || !strings.Contains(err.Error(), "does not support management boot fault persistence") {
		t.Fatalf("unsupported store did not return a capability error: %v", err)
	}
}
