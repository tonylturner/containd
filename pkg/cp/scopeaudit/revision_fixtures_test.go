// SPDX-License-Identifier: Apache-2.0
package scopeaudit

import (
	"context"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func testBaseRevision(store config.Store, ctx context.Context) config.Revision {
	snapshot, err := store.ReadSnapshot(ctx, config.SnapshotRevision, false)
	if err != nil {
		panic(err)
	}
	return snapshot.Revision
}
func testSaveCandidate(store config.Store, ctx context.Context, cfg *config.Config) error {
	_, err := store.SaveCandidate(ctx, testBaseRevision(store, ctx), cfg)
	return err
}
