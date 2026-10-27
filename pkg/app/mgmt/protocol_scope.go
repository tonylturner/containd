// SPDX-License-Identifier: Apache-2.0
package mgmtapp

import (
	"context"
	"github.com/tonylturner/containd/pkg/cp/scopeaudit"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
)

func publishScopeMigrations(ctx context.Context, stores mgmtStores) ([]dpevents.Event, error) {
	return scopeaudit.Publish(ctx, stores.store, stores.auditStore)
}
