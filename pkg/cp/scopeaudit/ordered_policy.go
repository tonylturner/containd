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

const OrderedPolicyKind = "config.ordered_policy.migrated"
const ForwardWarningKind = "config.forward.grant_omitted"

type orderedReader interface {
	OrderedPolicyMigrations(context.Context) ([]config.OrderedPolicyMigration, error)
}

func orderedKind(rec config.OrderedPolicyMigration) string {
	if rec.Kind == "publish" {
		return ForwardWarningKind
	}
	return OrderedPolicyKind
}

func orderedEvents(ctx context.Context, store config.Store) ([]dpevents.Event, error) {
	reader, ok := store.(orderedReader)
	if !ok {
		return nil, nil
	}
	records, err := reader.OrderedPolicyMigrations(ctx)
	if err != nil {
		return nil, err
	}
	var out []dpevents.Event
	for _, rec := range records {
		id := rec.ID
		switch rec.Bank {
		case "candidate":
			id++
		case "previous":
			id += 2
		}
		out = append(out, dpevents.Event{ID: id, Timestamp: rec.Timestamp, Proto: "system", Kind: orderedKind(rec),
			Attributes: map[string]any{"bank": rec.Bank, "beforeRuleIds": rec.Before, "afterRuleIds": rec.After,
				"forwards": rec.Forwards, "warnings": rec.Warnings, "schemaBefore": rec.SchemaBefore, "schemaAfter": rec.SchemaAfter}})
	}
	return out, nil
}

func publishOrdered(ctx context.Context, store config.Store, log audit.Store) error {
	reader, ok := store.(orderedReader)
	if !ok {
		return nil
	}
	records, err := reader.OrderedPolicyMigrations(ctx)
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
		kind := orderedKind(rec)
		if err := once.AddOnce(ctx, fmt.Sprintf("%s.%d.%s", kind, rec.ID, rec.Bank), audit.Record{
			Timestamp: rec.Timestamp, Actor: "system", Source: "management", Action: kind,
			Target: rec.Bank, Result: "success", Detail: string(blob),
		}); err != nil {
			return err
		}
	}
	return nil
}
