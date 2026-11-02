// SPDX-License-Identifier: Apache-2.0
package sshserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestSSHLocalFilesystem(t *testing.T) {
	srv, store, _ := newAssuranceServer(t)
	var downloads, edits atomic.Int32
	srv.opts.APIClient = secretHTTPClient(func(r *http.Request) (*http.Response, error) {
		var body []byte
		if r.Body != nil {
			var err error
			body, err = io.ReadAll(r.Body)
			if err != nil {
				return nil, err
			}
		}
		switch r.URL.Path {
		case "/api/v1/config/backups/id":
			downloads.Add(1)
			return jsonResponse(200, map[string]string{"description": "downloaded"}), nil
		case "/api/v1/services/vpn":
			if r.Method == http.MethodPost {
				var payload struct {
					Wireguard struct{ PrivateKey string }
				}
				if err := json.Unmarshal(body, &payload); err != nil {
					return nil, err
				}
				if payload.Wireguard.PrivateKey != "PRIVATE" || r.Header.Get("X-Containd-If-Revision") != "0123456789abcdef.1" {
					return nil, fmt.Errorf("credential edit lost value or revision")
				}
				edits.Add(1)
			}
			resp := jsonResponse(200, map[string]any{})
			resp.Header.Set("X-Containd-Revision", "0123456789abcdef.1")
			resp.Header.Set("X-Containd-Config", "staged")
			return resp, nil
		case "/api/v1/auth/me":
			return jsonResponse(200, map[string]string{"username": "operator", "role": "admin"}), nil
		default:
			return jsonResponse(200, map[string]any{}), nil
		}
	})
	addr := serveSSH(t, srv)
	u, password := createAdmin(t, store, "filesystem-admin")
	client, err := dialSSH(addr, u.Username, nil, ssh.Password(password))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	path := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(path, []byte("PRIVATE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"exec", "repl"} {
		t.Run(mode, func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "download")
			lines := []string{
				fmt.Sprintf("download backup id %q", target),
				fmt.Sprintf("set vpn wireguard private-key-file %q", path),
			}
			if mode == "exec" {
				for _, line := range lines {
					session, err := client.NewSession()
					if err != nil {
						t.Fatal(err)
					}
					output, err := session.CombinedOutput(line)
					session.Close()
					if err != nil {
						t.Fatalf("exec failed: %v %s", err, output)
					}
				}
			} else {
				session, err := client.NewSession()
				if err != nil {
					t.Fatal(err)
				}
				defer session.Close()
				var output bytes.Buffer
				session.Stdout, session.Stderr = &output, io.Discard
				session.Stdin = strings.NewReader(strings.Join(lines, "\n") + "\nexit\n")
				if err := session.Shell(); err != nil {
					t.Fatal(err)
				}
				if err := session.Wait(); err != nil {
					t.Fatalf("REPL failed: %v %s", err, &output)
				}
				if !strings.Contains(output.String(), "Downloaded to private file:") || !strings.Contains(output.String(), "staged;") {
					t.Fatalf("REPL did not execute file commands: %s", &output)
				}
			}
			body, err := os.ReadFile(target)
			if err != nil || !strings.Contains(string(body), "downloaded") {
				t.Fatalf("SSH did not download file: %v", err)
			}
		})
	}
	if downloads.Load() != 2 || edits.Load() != 2 {
		t.Fatalf("downloads=%d edits=%d", downloads.Load(), edits.Load())
	}
}
