// SPDX-License-Identifier: Apache-2.0
package config

import (
	"context"
	"time"
)

func testBaseRevision(store Store, ctx context.Context) Revision {
	snapshot, err := store.ReadSnapshot(ctx, SnapshotRevision, false)
	if err != nil {
		panic(err)
	}
	return snapshot.Revision
}
func testApplyChange(store RuntimeStore, ctx context.Context, change RunningChange, ttl time.Duration, apply func(context.Context, *Config, *Config) error) error {
	_, err := store.ApplyChange(ctx, testBaseRevision(store, ctx), change, ttl, apply)
	return err
}
func testApplyReset(store *SQLiteStore, ctx context.Context, cfg *Config, apply func(context.Context, *Config, *Config) error) error {
	_, err := store.ApplyReset(ctx, testBaseRevision(store, ctx), cfg, apply)
	return err
}
func testCommit(store Store, ctx context.Context) error {
	_, err := store.Commit(ctx, testBaseRevision(store, ctx))
	return err
}
func testCommitConfirmed(store Store, ctx context.Context, ttl time.Duration) error {
	_, err := store.CommitConfirmed(ctx, testBaseRevision(store, ctx), ttl)
	return err
}
func testConfirmCommit(store Store, ctx context.Context) error {
	_, err := store.ConfirmCommit(ctx, testBaseRevision(store, ctx))
	return err
}
func testMutateCandidate(store Store, ctx context.Context, edit func(*Config) error) error {
	_, err := store.MutateCandidate(ctx, testBaseRevision(store, ctx), edit)
	return err
}
func testMutateCandidateIDS(store IDSCandidateStore, ctx context.Context, edit func(*Config) error) error {
	_, err := store.MutateCandidateIDS(ctx, testBaseRevision(store, ctx), edit)
	return err
}
func testRollback(store Store, ctx context.Context) error {
	_, err := store.Rollback(ctx, testBaseRevision(store, ctx))
	return err
}
func testSaveCandidate(store Store, ctx context.Context, cfg *Config) error {
	_, err := store.SaveCandidate(ctx, testBaseRevision(store, ctx), cfg)
	return err
}
