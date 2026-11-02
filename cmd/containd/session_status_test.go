// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	httpapi "github.com/tonylturner/containd/api/http"
	mgmtapp "github.com/tonylturner/containd/pkg/app/mgmt"
	"github.com/tonylturner/containd/pkg/cli"
	"github.com/tonylturner/containd/pkg/cp/config"
)

// Run the executable's real runtime-record client, login, liner input, command
// dispatch and prompt rendering, rather than testing just a cached snapshot.
func TestLocalStatusHTTPPrompts(t *testing.T) {
	for _, failure := range []string{"none", "timeout", "unauthorized"} {
		t.Run(failure, func(t *testing.T) {
			root := t.TempDir()
			t.Setenv(cli.EnvSSHAPISocket, "")
			t.Setenv("CONTAIND_CONFIG_DB", filepath.Join(root, "config.db"))
			t.Setenv("CONTAIND_CLI_HISTORY", filepath.Join(root, "history"))
			t.Setenv("CONTAIND_CLI_USER", "operator")
			t.Setenv("CONTAIND_CLI_PASSWORD", "password")
			bound := config.BoundManagementListeners()
			t.Cleanup(func() {
				config.SetBoundManagementListeners(bound)
				httpapi.SetServedManagement(httpapi.ServedManagement{})
			})
			var mu sync.Mutex
			hostname, token, calls := "containd", "login-token", 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				mu.Lock()
				defer mu.Unlock()
				if r.URL.Path == "/api/v1/auth/login" {
					var login map[string]string
					if json.Unmarshal(body, &login) != nil || login["username"] != "operator" || login["password"] != "password" {
						t.Error("wrong login credentials")
					}
					_, _ = io.WriteString(w, `{"token":"login-token"}`)
					return
				}
				if r.Header.Get("Authorization") != "Bearer "+token {
					t.Errorf("missing or outdated bearer on %s", r.URL.Path)
					w.WriteHeader(401)
					return
				}
				switch r.URL.Path {
				case "/api/v1/auth/me":
					_, _ = io.WriteString(w, `{"username":"operator","role":"admin"}`)
				case "/api/v1/config":
					_, _ = io.WriteString(w, `{"system":{"hostname":"containd"}}`)
				case "/api/v1/config/diff":
					calls++
					if calls == 2 {
						switch failure {
						case "timeout":
							<-r.Context().Done()
							return
						case "unauthorized":
							w.WriteHeader(401)
							return
						}
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"changed": hostname != "containd"})
				case "/api/v1/config/candidate":
					w.Header().Set("X-Containd-Revision", "0123456789abcdef.1")
					if r.Method == http.MethodPost {
						var cfg config.Config
						if json.Unmarshal(body, &cfg) != nil || r.Header.Get("X-Containd-If-Revision") != "0123456789abcdef.1" {
							t.Error("invalid staged edit or missing revision")
							w.WriteHeader(400)
							return
						}
						hostname = cfg.System.Hostname
						w.Header().Set("X-Containd-Config", "staged")
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"system": map[string]string{"hostname": hostname}})
				default:
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()
			record := mgmtapp.RuntimeRecord{Listeners: config.ManagementListeners{HTTP: config.ManagementListener{Addr: srv.Listener.Addr().String(), Enabled: true}}}
			data, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			path := mgmtapp.RuntimeRecordPath()
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			input, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			_, err = io.WriteString(writer, "show version\nset system hostname status-test\nset system hostname containd\nexit\n")
			writer.Close()
			if err != nil {
				t.Fatal(err)
			}
			output, err := os.CreateTemp(root, "output")
			if err != nil {
				t.Fatal(err)
			}
			defer output.Close()
			stdin, stdout := os.Stdin, os.Stdout
			os.Stdin, os.Stdout = input, output
			defer func() { os.Stdin, os.Stdout = stdin, stdout }()
			start := time.Now()
			if err := runCLI(context.Background()); err != nil {
				t.Fatal(err)
			}
			elapsed := time.Since(start)
			data, err = os.ReadFile(output.Name())
			if err != nil {
				t.Fatal(err)
			}
			text := string(data)
			wantUnknown, wantClean := 0, 3
			if failure != "none" {
				wantUnknown, wantClean = 1, 2
			}
			if strings.Count(text, "containd(config)# ") != wantClean || strings.Count(text, "containd(config*)# ") != 1 || strings.Count(text, "containd(config?)# ") != wantUnknown {
				t.Fatalf("status never resolved, retained stale state, or failed to recover:\n%s", text)
			}
			mu.Lock()
			gotCalls, restored := calls, hostname == "containd"
			mu.Unlock()
			if gotCalls != 4 || !restored {
				t.Fatalf("status calls=%d restored=%v", gotCalls, restored)
			}
			if failure == "timeout" && (elapsed < 200*time.Millisecond || elapsed > 2*time.Second) {
				t.Fatalf("hung status exceeded short request budget: %s", elapsed)
			}
			if failure == "timeout" && !strings.Contains(text, "context deadline exceeded") || failure == "unauthorized" && !strings.Contains(text, "unexpected status 401") {
				t.Fatalf("failure cause hidden:\n%s", text)
			}
		})
	}
}
