// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// Import restores backups exported by releases that saved any shellMode, as
// the mode those releases ran; saving a new candidate stays strict.
func TestImportNormalizesLegacyShellModeAndSaveStaysStrict(t *testing.T) {
	store, err := config.NewSQLiteStore(filepath.Join(t.TempDir(), "cfg.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Save(context.Background(), config.DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	s := NewServer(store, nil)
	post := func(path, mode string) *httptest.ResponseRecorder {
		t.Helper()
		resetTestRateLimiters()
		cfg := config.DefaultConfig()
		cfg.System.SSH.ShellMode = mode
		body, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		req := authedRequest(http.MethodPost, path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		serveWithConfigRevision(t, s, rec, req)
		return rec
	}
	for backup, want := range map[string]string{"Linux": "linux", "LINUX": "linux", "linux": "linux", "bash": "appliance", "": ""} {
		if rec := post("/api/v1/config/import", backup); rec.Code != http.StatusOK {
			t.Fatalf("import %q: %d %s", backup, rec.Code, rec.Body.String())
		}
		candidate, err := store.LoadCandidate(context.Background())
		if err != nil || candidate.System.SSH.ShellMode != want {
			t.Fatalf("import %q staged %q (%v), want %q", backup, candidate.System.SSH.ShellMode, err, want)
		}
	}
	for _, mode := range []string{"Linux", "bash"} {
		rec := post("/api/v1/config/candidate", mode)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "ssh.shellMode") {
			t.Fatalf("save %q: %d %s", mode, rec.Code, rec.Body.String())
		}
	}
}
