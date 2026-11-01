// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/users"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"gopkg.in/yaml.v3"
)

func casRequest(t *testing.T, server http.Handler, method, path string, body any, revision string) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := authedRequest(method, "/api/v1"+path, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	if revision != "" {
		req.Header.Set(ifRevisionHeader, revision)
	}
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	return rec
}

func TestConfigRevisionPreconditionOrder(t *testing.T) {
	store := stageStore(t)
	server := NewServer(store, nil)
	base := testBaseRevision(store, context.Background())
	for _, test := range []struct {
		header string
		status int
		code   string
	}{
		{"", 428, "config_revision_required"},
		{"*", 400, "config_revision_malformed"},
		{string(base) + " ", 400, "config_revision_malformed"},
		{"\"" + string(base) + "\"", 400, "config_revision_malformed"},
		{string(base) + "," + string(base), 400, "config_revision_malformed"},
	} {
		req := authedRequest("POST", "/api/v1/config/candidate", bytes.NewBufferString("{"))
		if test.header != "" {
			req.Header.Set(ifRevisionHeader, test.header)
		}
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		if rec.Code != test.status || !bytes.Contains(rec.Body.Bytes(), []byte(test.code)) {
			t.Fatalf("precondition order: %d %s", rec.Code, rec.Body)
		}
	}
	req := httptest.NewRequest("POST", "/api/v1/config/candidate", bytes.NewBufferString("{"))
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("authentication must precede precondition: %d", rec.Code)
	}
	// Envelope validation belongs after auth and preconditions too, not in
	// outer group middleware that can mask a missing or stale client base.
	for _, test := range []struct {
		token, revision string
		status          int
	}{
		{"", "", 401}, {testAdminToken, "", 428}, {testAdminToken, "*", 400}, {testAdminToken, string(base), 413},
	} {
		req := httptest.NewRequest("POST", "/api/v1/config/candidate", bytes.NewBufferString("{"))
		req.ContentLength = defaultJSONBodyLimit + 1
		if test.token != "" {
			req.Header.Set("Authorization", "Bearer "+test.token)
		}
		if test.revision != "" {
			req.Header.Set(ifRevisionHeader, test.revision)
		}
		rec := httptest.NewRecorder()
		server.ServeHTTP(rec, req)
		if rec.Code != test.status {
			t.Fatalf("oversized precondition order: status=%d want=%d body=%s", rec.Code, test.status, rec.Body)
		}
	}
	if testBaseRevision(store, context.Background()) != base {
		t.Fatal("precondition rejection mutated state")
	}
}

func TestConfigRevisionEveryWriterRejectsStale(t *testing.T) {
	cases := configResponseStageCases()
	cases = append(cases,
		candidateEndpointCase{method: "POST", path: "/config/commit"},
		candidateEndpointCase{method: "POST", path: "/config/commit_confirmed", body: map[string]int{"ttl_seconds": 3600}},
		candidateEndpointCase{method: "POST", path: "/config/confirm"},
		candidateEndpointCase{method: "POST", path: "/config/rollback"},
		candidateEndpointCase{method: "POST", path: "/system/factory-reset", body: map[string]string{"confirm": "NUCLEAR"}},
		candidateEndpointCase{method: "POST", path: "/firewall/rules/old/move", body: map[string]string{"position": "bottom"}},
		candidateEndpointCase{method: "POST", path: "/firewall/port-forwards", body: json.RawMessage(`{"forward":` + publishForward + `}`)},
		candidateEndpointCase{method: "DELETE", path: "/firewall/port-forwards/f"},
		candidateEndpointCase{method: "POST", path: "/identities", body: map[string]any{"ip": "10.0.0.10", "identities": []string{"operator"}}},
		candidateEndpointCase{method: "DELETE", path: "/identities/10.0.0.10"},
	)
	fixtures := map[string]bool{"POST /api/v1/learn/apply": true} // learner engine fixtures are tested separately below
	for _, test := range cases {
		route := configWriterRoute(httptest.NewRequest(test.method, "/api/v1"+test.path, nil))
		if route == "" {
			t.Fatalf("unclassified writer fixture: %s %s", test.method, test.path)
		}
		fixtures[route] = true
	}
	for route, class := range mutationRouteClass {
		if class == "config-writer" && !fixtures[route] {
			t.Errorf("missing authenticated writer fixture: %s", route)
		}
	}
	for _, test := range cases {
		t.Run(test.method+test.path, func(t *testing.T) {
			resetTestRateLimiters()
			ctx := context.Background()
			uploadDir := t.TempDir()
			t.Setenv("CONTAIND_OPENVPN_DIR", uploadDir)
			store := stageStore(t)
			if test.path == "/config/confirm" || test.path == "/config/rollback" {
				if err := testCommitConfirmed(store, ctx, time.Hour); err != nil {
					t.Fatal(err)
				}
			}
			if test.path == "/firewall/port-forwards/f" || test.path == "/identities/10.0.0.10" {
				if err := testMutateCandidate(store, ctx, func(c *config.Config) error {
					if test.path == "/firewall/port-forwards/f" {
						var forward config.PortForward
						if err := json.Unmarshal([]byte(publishForward), &forward); err != nil {
							return err
						}
						c.Firewall.NAT.PortForwards = append(c.Firewall.NAT.PortForwards, forward)
						c.Firewall.Rules = append(c.Firewall.Rules, config.Rule{ID: "forward-allow", Action: config.ActionAllow, ViaForwards: []string{"f"}})
					} else {
						c.Firewall.IdentityBindings = []config.IdentityBinding{{IP: "10.0.0.10", Identities: []string{"operator"}}}
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			base := testBaseRevision(store, ctx)
			if err := testMutateCandidate(store, ctx, func(c *config.Config) error {
				c.Description = "concurrent edit"
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			userStore, err := users.NewSQLiteStore(filepath.Join(t.TempDir(), "users.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer userStore.Close()
			engine := &stageEngine{mockEngine: &mockEngine{}}
			server := NewServerWithEngineAndServices(store, nil, engine, nil, userStore)
			before, err := store.ReadSnapshot(ctx, config.SnapshotPair, true)
			if err != nil {
				t.Fatal(err)
			}
			for _, revision := range []string{"", string(base)} {
				var rec *httptest.ResponseRecorder
				if test.path == "/ids/import" {
					req := idsApplyRequest(t, "import")
					if revision != "" {
						req.Header.Set(ifRevisionHeader, revision)
					}
					rec = httptest.NewRecorder()
					server.ServeHTTP(rec, req)
				} else {
					rec = casRequest(t, server, test.method, test.path, test.body, revision)
				}
				want := 412
				if revision == "" {
					want = 428
				}
				if rec.Code != want {
					t.Fatalf("status=%d want=%d body=%s", rec.Code, want, rec.Body)
				}
				if want == 412 {
					var body struct {
						Code, CurrentRevision string
					}
					if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Code != "config_revision_mismatch" || body.CurrentRevision != string(before.Revision) {
						t.Fatalf("mismatch body: %s (%v)", rec.Body, err)
					}
				}
			}
			after, err := store.ReadSnapshot(ctx, config.SnapshotPair, true)
			if err != nil || !reflect.DeepEqual(before, after) || engine.mutations != 0 {
				t.Fatalf("stale write had effects: %v engine calls=%d", err, engine.mutations)
			}
			files, err := os.ReadDir(uploadDir)
			if err != nil || len(files) != 0 {
				t.Fatalf("rejected upload left files: %v %v", files, err)
			}
		})
	}
}

func TestConfigRevisionLearnUncertainPersistence(t *testing.T) {
	for _, releaseFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "released", true: "release uncertain"}[releaseFails], func(t *testing.T) {
			ctx := context.Background()
			store := stageStore(t)
			suggestion := stageProposal(t)
			engine := &evidenceStageEngine{
				stageEngine: &stageEngine{mockEngine: &mockEngine{}},
				frozen:      []learn.Suggestion{suggestion},
			}
			server := NewServerWithEngine(store, nil, engine)
			request := learn.ApplyRequest{RequestID: "reviewed-retry", Selections: []learn.Selection{{ID: suggestion.ID, Revision: suggestion.Revision}}}
			base := testBaseRevision(store, ctx)
			missing := casRequest(t, server, "POST", "/learn/apply", request, "")
			if missing.Code != 428 || engine.resolves != 0 {
				t.Fatal("missing precondition reached learner")
			}
			engine.completeError = errors.New("completion lost")
			staged := casRequest(t, server, "POST", "/learn/apply", request, string(base))
			persisted := testBaseRevision(store, ctx)
			if staged.Code != 503 || staged.Header().Get(revisionHeader) != "" || persisted == base {
				t.Fatalf("durable-stage error exposed revision or lost persistence: %d %s %v", staged.Code, staged.Body, staged.Header())
			}
			engine.completeError = nil
			if releaseFails {
				engine.releaseError = errors.New("release lost")
			}
			stale := casRequest(t, server, "POST", "/learn/apply", request, string(base))
			want := 412
			if releaseFails {
				want = 503
			}
			if stale.Code != want || engine.done != 1 || engine.releases != 1 || testBaseRevision(store, ctx) != persisted {
				t.Fatalf("stale stage had effects: %d %s %+v", stale.Code, stale.Body, engine)
			}
			engine.releaseError = nil
			// An explicit operator re-read/review authorizes the same receipt.
			review := casRequest(t, server, "GET", "/config/candidate", nil, "")
			retry := casRequest(t, server, "POST", "/learn/apply", request, review.Header().Get(revisionHeader))
			if retry.Code != 200 || engine.done != 2 {
				t.Fatalf("reviewed retry: %d %s", retry.Code, retry.Body)
			}
		})
	}
}

type interleavedSnapshotStore struct {
	*config.SQLiteStore
	captured chan config.ConfigSnapshot
	resume   chan struct{}
	once     sync.Once
}

func (s *interleavedSnapshotStore) ReadSnapshot(ctx context.Context, kind config.SnapshotKind, bank bool) (config.ConfigSnapshot, error) {
	result, err := s.SQLiteStore.ReadSnapshot(ctx, kind, bank)
	s.once.Do(func() {
		s.captured <- result
		<-s.resume
	})
	return result, err
}

func TestConfigRevisionReadWriteCoherence(t *testing.T) {
	store := &interleavedSnapshotStore{SQLiteStore: stageStore(t), captured: make(chan config.ConfigSnapshot, 1), resume: make(chan struct{})}
	server := NewServer(store, nil)
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		server.ServeHTTP(rec, authedRequest("GET", "/api/v1/config/candidate", nil))
		close(done)
	}()
	snapshot := <-store.captured
	cfg := config.DefaultConfig()
	cfg.Description = "new write before old read response"
	next, err := store.SQLiteStore.SaveCandidate(context.Background(), snapshot.Revision, cfg)
	close(store.resume)
	<-done
	if err != nil {
		t.Fatal(err)
	}
	var body config.Config
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if rec.Code != 200 || rec.Header().Get(revisionHeader) != string(snapshot.Revision) || rec.Header().Get(revisionHeader) == string(next) || body.Description != snapshot.Candidate.Description {
		t.Fatalf("torn read: %d %s %v", rec.Code, rec.Body, rec.Header())
	}
}

func TestConfigRevisionReadHeaders(t *testing.T) {
	store := stageStore(t)
	base := testBaseRevision(store, context.Background())
	server := NewServer(store, nil)
	for _, path := range []string{
		"/config", "/config/candidate", "/config/diff", "/config/export",
		"/ids/export", "/ids/backup", "/firewall/rules", "/firewall/ics-rules",
		"/firewall/nat", "/assets", "/objects", "/zones", "/interfaces",
		"/routing", "/dataplane", "/pcap/config", "/ids/rules", "/identities",
		"/services/syslog", "/services/dns", "/services/ntp", "/services/av",
		"/services/dhcp", "/services/vpn", "/services/proxy/forward",
		"/services/proxy/reverse",
	} {
		t.Run(path, func(t *testing.T) {
			rec := casRequest(t, server, "GET", path, nil, "")
			if rec.Code != 200 || rec.Header().Get(revisionHeader) != string(base) {
				t.Fatalf("read lost snapshot revision: %d %s %v", rec.Code, rec.Body, rec.Header())
			}
			assertConfigResponseHeader(t, rec, "")
			var body map[string]any
			if json.Unmarshal(rec.Body.Bytes(), &body) == nil {
				if _, exists := body["revision"]; exists {
					t.Fatal("revision must be header-only")
				}
			}
		})
	}
}

func TestOpenAPIConfigRevisions(t *testing.T) {
	data, err := os.ReadFile("../../docs/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Paths map[string]map[string]struct {
			Parameters []struct {
				Ref string `yaml:"$ref"`
			}
			Responses map[string]struct {
				Headers map[string]any
			}
		}
	}
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}
	for route, class := range mutationRouteClass {
		if class != "config-writer" {
			continue
		}
		method, path, _ := strings.Cut(route, " ")
		path = strings.TrimPrefix(path, "/api/v1")
		for _, name := range []string{"id", "ip", "name"} {
			path = strings.ReplaceAll(path, ":"+name, "{"+name+"}")
		}
		op := spec.Paths[path][strings.ToLower(method)]
		found := false
		for _, param := range op.Parameters {
			found = found || param.Ref == "#/components/parameters/IfRevision" || route == "POST /api/v1/templates/ics/apply" && param.Ref == "#/components/parameters/TemplateIfRevision"
		}
		if !found {
			t.Errorf("%s lacks the precondition parameter", route)
		}
		for _, status := range []string{"412", "428"} {
			if _, ok := op.Responses[status]; !ok {
				t.Errorf("%s lacks %s", route, status)
			}
		}
		for status, response := range op.Responses {
			if strings.HasPrefix(status, "2") && response.Headers[revisionHeader] == nil {
				t.Errorf("%s %s lacks the resulting revision", route, status)
			}
		}
	}
}

func TestConfigRevisionTemplatePreviewIsReadOnly(t *testing.T) {
	store := stageStore(t)
	ctx := context.Background()
	base := testBaseRevision(store, ctx)
	if err := testMutateCandidate(store, ctx, func(c *config.Config) error { c.Description = "newer"; return nil }); err != nil {
		t.Fatal(err)
	}
	current := testBaseRevision(store, ctx)
	rec := casRequest(t, NewServer(store, nil), "POST", "/templates/ics/apply", map[string]any{"template": "modbus_read_only", "preview": true}, string(base))
	if rec.Code != 200 || testBaseRevision(store, ctx) != current || rec.Header().Get(revisionHeader) != "" {
		t.Fatalf("preview performed a transition: %d %s", rec.Code, rec.Body)
	}
	assertConfigResponseHeader(t, rec, "")
}

type refusingProfileStore struct{ *config.SQLiteStore }

func (s *refusingProfileStore) MutateCandidate(ctx context.Context, expected config.Revision, edit func(*config.Config) error) (config.Revision, error) {
	return s.SQLiteStore.MutateCandidate(ctx, expected, func(c *config.Config) error {
		if err := edit(c); err != nil {
			return err
		}
		return errors.New("profile refused after artifact creation")
	})
}

func TestConfigRevisionVPNRefusalCleanup(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("CONTAIND_OPENVPN_DIR", directory)
	store := &refusingProfileStore{stageStore(t)}
	base := testBaseRevision(store, context.Background())
	rec := casRequest(t, NewServer(store, nil), "POST", "/services/vpn/openvpn/profile", map[string]string{"name": "profile", "ovpn": "client\nremote 192.0.2.1 1194\n"}, string(base))
	files, err := os.ReadDir(directory)
	if rec.Code != 400 || err != nil || len(files) != 0 || testBaseRevision(store, context.Background()) != base {
		t.Fatalf("failed profile left effects: status=%d files=%v err=%v", rec.Code, files, err)
	}
}
