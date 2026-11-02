// SPDX-License-Identifier: Apache-2.0
package cli_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	httpapi "github.com/tonylturner/containd/api/http"
	"github.com/tonylturner/containd/pkg/cli"
	"github.com/tonylturner/containd/pkg/cp/config"
)

type handlerClient struct {
	handler http.Handler
	t       *testing.T
	raw     string
	posts   int
	remote  string
}

var importClientSequence atomic.Uint64

func (c *handlerClient) Do(r *http.Request) (*http.Response, error) {
	r.RemoteAddr = c.remote
	if r.Method == "POST" {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			c.t.Fatal(err)
		}
		if string(body) != c.raw {
			c.t.Fatalf("import bytes changed: %s", body)
		}
		if r.Header.Get("X-Containd-If-Revision") == "" {
			c.t.Fatal("missing revision")
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		c.posts++
	}
	rec := httptest.NewRecorder()
	c.handler.ServeHTTP(rec, r)
	return rec.Result(), nil
}

func TestOpsImportStrictAPI(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "1")
	t.Setenv("CONTAIND_JWT_SECRET", "")
	store, err := config.NewSQLiteStore(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := cli.WithLocalFilesystem(cli.WithRole(context.Background(), "admin"), true)
	// Each invocation models a separate client. Repeated test runs must not
	// share the API's process-wide sensitive-write budget for one empty IP.
	remote := fmt.Sprintf("[2001:db8::%x]:12345", importClientSequence.Add(1))
	if err := store.Save(ctx, config.DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	handler := httpapi.NewServer(store, nil)
	for _, raw := range []string{
		`{"unexpected":true}`, `{"description":"first","description":"second"}`, `{"Description":"wrong case"}`,
	} {
		t.Run(raw, func(t *testing.T) {
			before, err := store.ReadSnapshot(ctx, config.SnapshotPair, true)
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(t.TempDir(), "import.json")
			if err := os.WriteFile(file, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			client := &handlerClient{handler: handler, t: t, raw: raw, remote: remote}
			api := &cli.API{BaseURL: "http://appliance", Token: "lab", Client: client}
			err = cli.NewRegistry(nil, api).Execute(ctx, "import config", io.Discard, []string{file})
			if err == nil || !strings.Contains(err.Error(), "400") || client.posts != 1 {
				t.Fatalf("not rejected by API: %v posts=%d", err, client.posts)
			}
			after, err := store.ReadSnapshot(ctx, config.SnapshotPair, true)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("candidate changed after refusal: %v", err)
			}
		})
	}
	raw := "{\n \"description\": \"imported\"\n}"
	file := filepath.Join(t.TempDir(), "valid.json")
	if err := os.WriteFile(file, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	client := &handlerClient{handler: handler, t: t, raw: raw, remote: remote}
	var out bytes.Buffer
	if err := cli.NewRegistry(nil, &cli.API{BaseURL: "http://appliance", Token: "lab", Client: client}).Execute(ctx, "import config", &out, []string{file}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.ReadSnapshot(ctx, config.SnapshotPair, true)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Candidate.Description != "imported" || snapshot.Running.Description == "imported" || !strings.Contains(out.String(), "staged;") {
		t.Fatalf("not staged: %s", &out)
	}
}
