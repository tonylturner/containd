// SPDX-License-Identifier: Apache-2.0
package scopeaudit

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestInterfaceDeviceEvidencePublishedOnce(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := config.NewSQLiteStore(filepath.Join(dir, "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg, err := config.DecodeRequestConfig([]byte(`{"schema_version":"0.1.10","interfaces":[{"name":"wan","device":"eth0"}],"firewall":{"defaultAction":"DENY"}}`), config.RequestConfigImport)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.UpgradeInPlace(cfg); err != nil {
		t.Fatal(err)
	}
	if err := testSaveCandidate(s, ctx, cfg); err != nil {
		t.Fatal(err)
	}
	log, err := audit.NewSQLiteStore(filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	for range 2 {
		events, err := Publish(ctx, s, log)
		if err != nil || len(events) != 1 || events[0].Kind != InterfaceDeviceKind || events[0].Attributes["bank"] != "candidate" {
			t.Fatal("migration event missing", events, err)
		}
	}
	records, err := log.List(ctx, 100)
	if err != nil || len(records) != 1 || records[0].Action != InterfaceDeviceKind || !strings.Contains(records[0].Detail, `"old":"eth0"`) {
		t.Fatal("audit duplicated or incomplete", records, err)
	}
}
