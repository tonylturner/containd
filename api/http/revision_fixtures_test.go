// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func testBaseRevision(store config.Store, ctx context.Context) config.Revision {
	snapshot, err := store.ReadSnapshot(ctx, config.SnapshotRevision, false)
	if err != nil {
		panic(err)
	}
	return snapshot.Revision
}
func testApplyChange(store config.RuntimeStore, ctx context.Context, change config.RunningChange, ttl time.Duration, apply func(context.Context, *config.Config, *config.Config) error) error {
	_, err := store.ApplyChange(ctx, testBaseRevision(store, ctx), change, ttl, apply)
	return err
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

// Legacy behavior fixtures acquire an explicit base before exercising their
// mutation. Precondition rejection tests call ServeHTTP directly instead.
func serveWithConfigRevision(t *testing.T, server http.Handler, writer http.ResponseWriter, request *http.Request) {
	t.Helper()
	if isConfigWriterRequest(request) && request.Header.Get(ifRevisionHeader) == "" {
		read := httptest.NewRecorder()
		readRequest := httptest.NewRequest(http.MethodGet, "/api/v1/config/candidate", nil)
		readRequest.Header = request.Header.Clone()
		server.ServeHTTP(read, readRequest)
		if revision := read.Header().Get(revisionHeader); revision != "" {
			request.Header.Set(ifRevisionHeader, revision)
		}
	}
	server.ServeHTTP(writer, request)
}

func withTestRevision(store config.Store, request *http.Request) *http.Request {
	request.Header.Set(ifRevisionHeader, string(testBaseRevision(store, context.Background())))
	return request
}
