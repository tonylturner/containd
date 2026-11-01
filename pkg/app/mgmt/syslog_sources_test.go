// SPDX-License-Identifier: Apache-2.0

package mgmtapp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/services"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
	"go.uber.org/zap"
)

type syslogMigrationStore struct {
	config.Store
	records []config.IndustrialScopeMigration
}

func (s *syslogMigrationStore) IndustrialScopeMigrations(context.Context) ([]config.IndustrialScopeMigration, error) {
	return s.records, nil
}

type syslogFailingAudit struct{ testAuditStore }

func (*syslogFailingAudit) Add(context.Context, audit.Record) error {
	return errors.New("audit unavailable")
}
func (*syslogFailingAudit) AddOnce(context.Context, string, audit.Record) error {
	return errors.New("audit unavailable")
}

func TestSyslogManagementNoticesAreAppendedOnceDespiteAuditFailure(t *testing.T) {
	log := zap.NewNop().Sugar()
	manager := &bootEventServices{Manager: services.NewManager(services.ManagerOptions{BaseDir: t.TempDir()})}
	configStore := &syslogMigrationStore{}
	read := managementEventFeed(manager, mgmtStores{store: configStore, auditStore: &syslogFailingAudit{}}, log)
	initial, err := read(context.Background(), dpevents.FeedRequest{TailOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	configStore.records = []config.IndustrialScopeMigration{{ID: 10, Timestamp: time.Unix(1, 0)}, {ID: 3, Timestamp: time.Unix(2, 0)}}
	manager.event = &dpevents.Event{ID: 100, Kind: "management.recovery.boot_fault"}
	p, err := read(context.Background(), dpevents.FeedRequest{Epoch: initial.Epoch, After: initial.Tail})
	if err != nil || len(p.Records) != 3 || p.Records[0].Event.ID != 3 || p.Records[1].Event.ID != 10 || p.Records[2].Event.ID != 100 {
		t.Fatalf("%+v %v", p, err)
	}
	again, err := read(context.Background(), dpevents.FeedRequest{Epoch: p.Epoch, After: p.Tail})
	if err != nil || again.Tail != p.Tail || len(again.Records) != 0 {
		t.Fatalf("notice replay duplicated appends: %+v %v", again, err)
	}
	// The decision itself still persists; failed audit evidence must not lock
	// out management or discard the boot telemetry.
	event, err := persistBootFault(log, mgmtStores{store: &bootFaultRecordingStore{}, auditStore: &syslogFailingAudit{}}, errors.New("stored conflict"), nil)
	if err != nil || event == nil || event.Kind != "management.recovery.boot_fault" {
		t.Fatalf("audit failure aborted management recovery: %+v %v", event, err)
	}
}
