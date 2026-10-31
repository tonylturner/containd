// SPDX-License-Identifier: Apache-2.0
package engineapp

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	engineapi "github.com/tonylturner/containd/api/engine"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/evidence"
	"github.com/tonylturner/containd/pkg/evidence/sqlite"
)

func newEvidenceTestAPI(t testing.TB) *evidenceAPI {
	t.Helper()
	e, err := engine.New(engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	s, err := sqlite.Open(filepath.Join(t.TempDir(), "evidence.db"), sqlite.Options{CompatibleProof: learn.CompatibleVersions, WatchMetadata: func() (evidence.Dataset, error) { return evidenceMetadata(e) }})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	w := newEvidenceWatch(ctx, s, e)
	t.Cleanup(func() { e.SetLearnWatchHook(nil); cancel(); <-w.done; <-w.maintained; _ = s.Close() })
	return &evidenceAPI{store: s, watch: w, generator: &learn.Generator{Store: s, Certifier: &learn.CompilerCertifier{Store: s}, CountWithheld: s.CountWithheld}}
}
func TestEvidenceWatchRoundTrip(t *testing.T) {
	a := newEvidenceTestAPI(t)
	mux := http.NewServeMux()
	a.register(mux)
	server := httptest.NewServer(mux)
	defer server.Close()
	client := engineapi.NewHTTPClient(server.URL)
	ctx := context.Background()
	exchange := func(method, path, body string) json.RawMessage {
		t.Helper()
		data, err := client.Learn(ctx, method, path, "admin", json.RawMessage(body))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	for _, path := range []string{"/learn/watches", "/learn/datasets", "/learn/counters"} {
		exchange("GET", path, "")
	}
	var watch evidence.Watch
	if err := json.Unmarshal(exchange("POST", "/learn/watches", `{}`), &watch); err != nil {
		t.Fatal(err)
	}
	state := flow.NewState(flow.Key{SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2"), SrcPort: 40000, DstPort: 502, Proto: 6, Dir: flow.DirForward}, time.Now())
	a.watch.engine.RecordDPIEvents(state, nil, []dpi.Event{{Proto: "modbus", Kind: "request", Timestamp: time.Now(), Attributes: map[string]any{"function_code": uint8(3), "unit_id": uint8(0), "address": uint16(4), "quantity": uint16(2), "is_write": false}}})
	exchange("POST", "/learn/watches/"+watch.ID+"/stop", "")
	var dataset evidence.Dataset
	if err := json.Unmarshal(exchange("GET", "/learn/datasets/"+watch.DatasetID, ""), &dataset); err != nil {
		t.Fatal(err)
	}
	if dataset.State != evidence.DatasetSealed || dataset.Records != 1 || len(dataset.Gaps) > 0 {
		t.Fatalf("lost whole parent: %+v", dataset)
	}
	body, _ := json.Marshal(learn.GenerateRequest{DatasetID: dataset.ID})
	var result learn.GenerateResult
	if err := json.Unmarshal(exchange("POST", "/learn/generate", string(body)), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Suggestions) != 1 {
		t.Fatalf("no certified suggestion: %+v", result)
	}
	for _, path := range []string{"/internal/learn/profiles", "/internal/learn/rules", "/internal/learn"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 404 {
			t.Fatalf("legacy route survived: %s = %d", path, rec.Code)
		}
	}
}
