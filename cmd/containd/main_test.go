// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	httpapi "github.com/tonylturner/containd/api/http"
	mgmtapp "github.com/tonylturner/containd/pkg/app/mgmt"
	"github.com/tonylturner/containd/pkg/cli"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestCLILoopExitStatus(t *testing.T) {
	tests := []struct {
		name        string
		lines       []string
		interactive bool
		failCommand string
		wantStatus  int
		wantCalls   int
	}{
		{
			name:        "failed command then EOF",
			lines:       []string{"broken", "ok"},
			failCommand: "broken",
			wantStatus:  1,
			wantCalls:   2,
		},
		{
			name:       "all commands succeed",
			lines:      []string{"ok", "exit"},
			wantStatus: 0,
			wantCalls:  1,
		},
		{
			name:        "failed command then exit",
			lines:       []string{"broken", "exit"},
			failCommand: "broken",
			wantStatus:  1,
			wantCalls:   1,
		},
		{
			name:        "interactive command failure",
			lines:       []string{"broken", "exit"},
			interactive: true,
			failCommand: "broken",
			wantStatus:  0,
			wantCalls:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			lineIndex := 0
			readLine := func(string) (string, error) {
				if lineIndex >= len(tt.lines) {
					return "", io.EOF
				}
				line := tt.lines[lineIndex]
				lineIndex++
				return line, nil
			}
			calls := 0
			err := runCLILoop(
				"containd# ",
				readLine,
				func(string) {},
				func(line string, output *strings.Builder) error {
					calls++
					if line == tt.failCommand {
						return errors.New("authoritative config read failed")
					}
					output.WriteString("ok")
					return nil
				},
				tt.interactive,
				&stdout,
				&stderr,
			)
			if got := exitCode(context.Background(), err); got != tt.wantStatus {
				t.Errorf("exitCode = %d, want %d (err %v)", got, tt.wantStatus, err)
			}
			if calls != tt.wantCalls {
				t.Errorf("executed %d commands, want %d", calls, tt.wantCalls)
			}
			if tt.failCommand != "" && !strings.Contains(stderr.String(), "authoritative config read failed") {
				t.Errorf("stderr %q does not include command error", stderr.String())
			}
		})
	}
}

// Outside an SSH shell the CLI and the container health check call the
// listener management's runtime record names, and report management as not
// running without it.
func TestCLIAPIUsesManagementRuntimeRecord(t *testing.T) {
	t.Setenv(cli.EnvSSHAPISocket, "")
	t.Setenv("CONTAIND_CONFIG_DB", filepath.Join(t.TempDir(), "config.db"))
	t.Setenv(config.EnvManagementHTTPAddr, "127.0.0.1:1") // ignored: the record decides
	bound := config.BoundManagementListeners()
	t.Cleanup(func() {
		config.SetBoundManagementListeners(bound)
		httpapi.SetServedManagement(httpapi.ServedManagement{})
	})

	if _, err := cliAPI(context.Background()); err == nil || !strings.Contains(err.Error(), "management is not running") {
		t.Fatalf("without a record: %v", err)
	}
	if err := runHealthcheck(); err == nil || !strings.Contains(err.Error(), "management is not running") {
		t.Fatalf("healthcheck without a record: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/auth/login" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"token": "session-token"})
	}))
	defer srv.Close()
	rec := mgmtapp.RuntimeRecord{Listeners: config.ManagementListeners{HTTP: config.ManagementListener{Addr: srv.Listener.Addr().String(), Enabled: true}}}
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	path := mgmtapp.RuntimeRecordPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	api, err := cliAPI(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if api.BaseURL != srv.URL || api.Token != "session-token" || api.Client == nil {
		t.Fatalf("api %q token %q client %v", api.BaseURL, api.Token, api.Client)
	}
	if err := runHealthcheck(); err != nil {
		t.Fatalf("healthcheck: %v", err)
	}
}
