// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/peterh/liner"

	httpapi "github.com/tonylturner/containd/api/http"
	mgmtapp "github.com/tonylturner/containd/pkg/app/mgmt"
	"github.com/tonylturner/containd/pkg/cli"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestCLIInterruptCancelsOnlyInput(t *testing.T) {
	reads, calls := 0, 0
	var output strings.Builder
	err := runCLILoop("containd(config?)# ", func(string) (string, error) {
		reads++
		switch reads {
		case 1:
			return "", liner.ErrPromptAborted
		case 2:
			return "show version", nil
		default:
			return "", io.EOF
		}
	}, func(string) {}, func(string, *strings.Builder) error {
		calls++
		return nil
	}, true, &output, &output)
	if err != nil || calls != 1 || reads != 3 {
		t.Fatalf("interrupt ended session: err=%v calls=%d reads=%d", err, calls, reads)
	}
}

func TestCLILocalShellWordsDoNotExit(t *testing.T) {
	lines := []string{"shell", "bash", "show version", "exit"}
	index, calls := 0, 0
	var stdout, stderr strings.Builder
	reg := cli.NewRegistry(nil, nil)
	err := runCLILoop("containd(config?)# ", func(string) (string, error) {
		if index == len(lines) {
			return "", io.EOF
		}
		line := lines[index]
		index++
		return line, nil
	}, func(string) {}, func(line string, out *strings.Builder) error {
		calls++
		return cli.SessionCommandError(line, reg.ParseAndExecute(context.Background(), line, out))
	}, false, &stdout, &stderr)
	if !errors.Is(err, errCLISessionCommandFailed) || calls != 3 || index != 4 ||
		!strings.Contains(stdout.String(), "containd") ||
		!strings.Contains(stderr.String(), "unknown command: shell") ||
		!strings.Contains(stderr.String(), "unknown command: bash") {
		t.Fatalf("shell word ended session: err=%v calls=%d lines=%d stdout=%q stderr=%q", err, calls, index, stdout.String(), stderr.String())
	}
}

func TestCLIExitAliases(t *testing.T) {
	for _, alias := range []string{"exit", "quit", "logout"} {
		t.Run(alias, func(t *testing.T) {
			var output strings.Builder
			err := runCLILoop("containd(config?)# ", func(string) (string, error) {
				return alias, nil
			}, func(string) {}, func(string, *strings.Builder) error {
				t.Fatal("exit control executed as a command")
				return nil
			}, true, &output, &output)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

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

func TestCLILocalFilesystem(t *testing.T) {
	root := t.TempDir()
	t.Setenv(cli.EnvSSHAPISocket, "")
	t.Setenv("CONTAIND_CONFIG_DB", filepath.Join(root, "config.db"))
	t.Setenv("CONTAIND_CLI_HISTORY", filepath.Join(root, "history"))
	var edits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/auth/login":
			_, _ = io.WriteString(w, `{"token":"session-token"}`)
		case "/api/v1/auth/me":
			_, _ = io.WriteString(w, `{"username":"operator","role":"admin"}`)
		case "/api/v1/config/backups/id":
			_, _ = io.WriteString(w, `{"description":"downloaded"}`)
		case "/api/v1/services/vpn":
			if r.Method == http.MethodPost {
				var payload struct {
					Wireguard struct{ PrivateKey string }
				}
				if err := json.Unmarshal(body, &payload); err != nil || payload.Wireguard.PrivateKey != "PRIVATE" ||
					r.Header.Get("X-Containd-If-Revision") != "0123456789abcdef.1" {
					t.Error("local credential edit lost value or revision")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				edits.Add(1)
				w.Header().Set("X-Containd-Config", "staged")
			}
			w.Header().Set("X-Containd-Revision", "0123456789abcdef.1")
			_, _ = io.WriteString(w, `{}`)
		default:
			_, _ = io.WriteString(w, `{}`)
		}
	}))
	defer srv.Close()
	record := mgmtapp.RuntimeRecord{Listeners: config.ManagementListeners{HTTP: config.ManagementListener{Addr: srv.Listener.Addr().String(), Enabled: true}}}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	recordPath := mgmtapp.RuntimeRecordPath()
	if err := os.MkdirAll(filepath.Dir(recordPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recordPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	credential, target := filepath.Join(root, "credential"), filepath.Join(root, "download")
	if err := os.WriteFile(credential, []byte("PRIVATE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	input, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	if _, err := fmt.Fprintf(writer, "download backup id %q\nset vpn wireguard private-key-file %q\nexit\n", target, credential); err != nil {
		writer.Close()
		t.Fatal(err)
	}
	writer.Close()
	stdin := os.Stdin
	os.Stdin = input
	defer func() { os.Stdin = stdin }()
	if err := runCLI(context.Background()); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(target)
	if err != nil || !strings.Contains(string(body), "downloaded") || edits.Load() != 1 {
		t.Fatalf("local file commands did not execute: %v edits=%d", err, edits.Load())
	}
}
