// SPDX-License-Identifier: Apache-2.0
package mgmtapp

import (
	"context"
	"github.com/tonylturner/containd/pkg/cp/config"
	"time"
)

func testBaseRevision(store config.Store, ctx context.Context) config.Revision {
	snapshot, err := store.ReadSnapshot(ctx, config.SnapshotRevision, false)
	if err != nil {
		panic(err)
	}
	return snapshot.Revision
}
func testCommit(store config.Store, ctx context.Context) error {
	_, err := store.Commit(ctx, testBaseRevision(store, ctx))
	return err
}
func testCommitConfirmed(store config.Store, ctx context.Context, ttl time.Duration) error {
	_, err := store.CommitConfirmed(ctx, testBaseRevision(store, ctx), ttl)
	return err
}
func testMutateCandidate(store config.Store, ctx context.Context, edit func(*config.Config) error) error {
	_, err := store.MutateCandidate(ctx, testBaseRevision(store, ctx), edit)
	return err
}
func testMutateCandidateIDS(store config.IDSCandidateStore, ctx context.Context, edit func(*config.Config) error) error {
	_, err := store.MutateCandidateIDS(ctx, testBaseRevision(store, ctx), edit)
	return err
}
func testRollback(store config.Store, ctx context.Context) error {
	_, err := store.Rollback(ctx, testBaseRevision(store, ctx))
	return err
}
func testSaveCandidate(store config.Store, ctx context.Context, cfg *config.Config) error {
	_, err := store.SaveCandidate(ctx, testBaseRevision(store, ctx), cfg)
	return err
}
