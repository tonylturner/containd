// SPDX-License-Identifier: Apache-2.0
package scopeaudit

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
)

const RuleModesKind = "config.rule_modes.migrated"

type modeReader interface {
	RuleModeMigrations(context.Context) ([]config.RuleModeMigration, error)
}

func modeEvents(ctx context.Context, store config.Store) ([]dpevents.Event, error) {
	reader, ok := store.(modeReader)
	if !ok {
		return nil, nil
	}
	records, err := reader.RuleModeMigrations(ctx)
	if err != nil {
		return nil, err
	}
	var out []dpevents.Event
	for _, rec := range records {
		// Bank records have independent identities, including when promoted from
		// a single imported document. The original timestamp survives delivery.
		id := rec.ID
		switch rec.Bank {
		case "candidate":
			id++
		case "previous":
			id += 2
		}
		out = append(out, dpevents.Event{ID: id, Timestamp: rec.Timestamp, Proto: "system", Kind: RuleModesKind, Attributes: map[string]any{"bank": rec.Bank, "changes": rec.Changes, "schemaBefore": rec.SchemaBefore, "schemaAfter": rec.SchemaAfter}})
	}
	return out, nil
}

func publishModes(ctx context.Context, store config.Store, log audit.Store) error {
	reader, ok := store.(modeReader)
	if !ok {
		return nil
	}
	records, err := reader.RuleModeMigrations(ctx)
	if err != nil || len(records) == 0 {
		return err
	}
	once, ok := log.(interface {
		AddOnce(context.Context, string, audit.Record) error
	})
	if !ok {
		return fmt.Errorf("audit store does not support idempotent migration records")
	}
	for _, rec := range records {
		blob, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		if err := once.AddOnce(ctx, fmt.Sprintf("%s.%d.%s", RuleModesKind, rec.ID, rec.Bank), audit.Record{Timestamp: rec.Timestamp, Actor: "system", Source: "management", Action: RuleModesKind, Target: rec.Bank, Result: "success", Detail: string(blob)}); err != nil {
			return err
		}
	}
	return nil
}
