// SPDX-License-Identifier: Apache-2.0
package engineapp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/evidence"
	"github.com/tonylturner/containd/pkg/evidence/sqlite"
)

// EvidenceAPI owns explicit learner collection and its internal HTTP surface.
type EvidenceAPI struct {
	cancel    context.CancelFunc
	store     *sqlite.Store
	generator learn.Service
	watch     *evidenceWatch
}

// NewEvidenceAPI assembles a learner on an existing engine evidence authority.
// Close must precede closing store; the caller retains ownership of the store.
func NewEvidenceAPI(ctx context.Context, store *sqlite.Store, e *engine.Engine) *EvidenceAPI {
	ctx, cancel := context.WithCancel(ctx)
	return &EvidenceAPI{store: store, cancel: cancel, watch: newEvidenceWatch(ctx, store, e), generator: &learn.Generator{Store: store, Certifier: &learn.CompilerCertifier{Store: store}, CountWithheld: store.CountWithheld}}
}

// Close stops collection and waits for both collector workers.
func (a *EvidenceAPI) Close() {
	a.watch.engine.SetLearnWatchHook(nil)
	a.cancel()
	<-a.watch.done
	<-a.watch.maintained
}

func evidenceError(w http.ResponseWriter, err error) {
	status := 503
	switch {
	case errors.Is(err, sqlite.ErrNotFound):
		status = 404
	case errors.Is(err, learn.ErrExpired):
		status = 410
	case errors.Is(err, sqlite.ErrConflict), errors.Is(err, sqlite.ErrBudget), errors.Is(err, learn.ErrStale), errors.Is(err, learn.ErrNotCertified), errors.Is(err, learn.ErrReviewRequired):
		status = 409
	}
	http.Error(w, err.Error(), status)
}
func evidenceBody(w http.ResponseWriter, r *http.Request, v any) bool {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		http.Error(w, "invalid JSON", 400)
		return false
	}
	if err := d.Decode(new(any)); err != io.EOF {
		http.Error(w, "one JSON value required", 400)
		return false
	}
	return true
}
func evidencePage(w http.ResponseWriter, r *http.Request) (evidence.PageRequest, bool) {
	p := evidence.PageRequest{Limit: 200, Cursor: r.URL.Query().Get("cursor")}
	if len(p.Cursor) > 256 {
		http.Error(w, "invalid cursor", 400)
		return p, false
	}
	if text := r.URL.Query().Get("limit"); text != "" {
		n, err := strconv.Atoi(text)
		if err != nil || n < 1 || n > 200 {
			http.Error(w, "limit must be 1..200", 400)
			return p, false
		}
		p.Limit = n
	}
	return p, true
}

// Register installs engine-internal learner routes on mux.
func (a *EvidenceAPI) Register(mux *http.ServeMux) {
	for _, pattern := range []string{"POST /internal/learn/watches", "GET /internal/learn/watches", "GET /internal/learn/watches/{id}", "POST /internal/learn/watches/{id}/stop", "GET /internal/learn/datasets", "GET /internal/learn/datasets/{id}", "GET /internal/learn/datasets/{id}/observations", "DELETE /internal/learn/datasets/{id}", "POST /internal/learn/generate", "GET /internal/learn/suggestions", "GET /internal/learn/suggestions/{id}", "POST /internal/learn/suggestions/{id}/review", "GET /internal/learn/counters", "POST /internal/learn/stage/resolve", "POST /internal/learn/stage/complete", "POST /internal/learn/stage/release"} {
		mux.HandleFunc(pattern, a.serve)
	}
}
func (a *EvidenceAPI) serve(w http.ResponseWriter, r *http.Request) {
	// Collector failures affect readiness, not authority reads or cleanup.
	var result any
	var err error
	ctx := r.Context()
	id := r.PathValue("id")
	switch r.Pattern {
	case "POST /internal/learn/watches":
		var req evidence.StartWatchRequest
		if !evidenceBody(w, r, &req) {
			return
		}
		if _, err := req.Duration(); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		result, err = a.watch.start(ctx, req)
	case "GET /internal/learn/watches":
		p, ok := evidencePage(w, r)
		if !ok {
			return
		}
		result, err = a.store.ListWatches(ctx, p)
	case "GET /internal/learn/watches/{id}":
		result, err = a.store.GetWatch(ctx, id)
	case "POST /internal/learn/watches/{id}/stop":
		result, err = a.watch.stop(ctx, id)
	case "GET /internal/learn/datasets":
		p, ok := evidencePage(w, r)
		if !ok {
			return
		}
		result, err = a.store.ListDatasets(ctx, p)
	case "GET /internal/learn/datasets/{id}":
		result, err = a.store.GetDataset(ctx, id)
	case "GET /internal/learn/datasets/{id}/observations":
		p, ok := evidencePage(w, r)
		if !ok {
			return
		}
		result, err = a.store.ListObservations(ctx, id, p)
	case "DELETE /internal/learn/datasets/{id}":
		err = a.store.DeleteDataset(ctx, id)
	case "POST /internal/learn/generate":
		var req learn.GenerateRequest
		if !evidenceBody(w, r, &req) {
			return
		}
		if req.DatasetID == "" {
			http.Error(w, "datasetId required", 400)
			return
		}
		result, err = a.generator.Generate(ctx, req)
	case "GET /internal/learn/suggestions":
		p, ok := evidencePage(w, r)
		if !ok {
			return
		}
		result, err = a.store.ListSuggestions(ctx, r.URL.Query().Get("datasetId"), p)
	case "GET /internal/learn/suggestions/{id}":
		result, err = a.store.GetSuggestion(ctx, id)
	case "POST /internal/learn/suggestions/{id}/review":
		var req learn.ReviewRequest
		if !evidenceBody(w, r, &req) {
			return
		}
		if req.Selection.ID != id || req.Selection.Revision == 0 {
			http.Error(w, "path selection and nonzero revision required", 400)
			return
		}
		actor := r.Header.Get("X-Containd-Review-Actor")
		if actor == "" {
			http.Error(w, "authenticated actor required", 400)
			return
		}
		result, err = a.store.ReviewSuggestion(ctx, actor, req)
	case "GET /internal/learn/counters":
		result, err = a.store.Counters(ctx)
	case "POST /internal/learn/stage/resolve", "POST /internal/learn/stage/complete", "POST /internal/learn/stage/release":
		var req learn.ApplyRequest
		if !evidenceBody(w, r, &req) {
			return
		}
		if err := sqlite.ValidateApply(req); err != nil {
			http.Error(w, "invalid stage selections", 400)
			return
		}
		if r.Pattern == "POST /internal/learn/stage/resolve" {
			result, err = a.store.ResolveForStage(ctx, req)
		} else if r.Pattern == "POST /internal/learn/stage/complete" {
			err = a.store.MarkStaged(ctx, req)
		} else {
			err = a.store.ReleaseStage(ctx, req)
		}
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		evidenceError(w, err)
		return
	}
	if result == nil {
		w.WriteHeader(204)
		return
	}
	writeJSON(w, result)
}
