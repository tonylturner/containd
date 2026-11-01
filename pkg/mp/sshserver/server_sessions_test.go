// SPDX-License-Identifier: Apache-2.0
package sshserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/ssh"
)

func TestFactoryResetDisconnectsSSHAfterResult(t *testing.T) {
	for _, secretless := range []bool{false, true} {
		for _, warning := range []bool{false, true} {
			name := "jwt"
			if secretless {
				name = "secretless"
			}
			if warning {
				name += "/warning"
			}
			t.Run(name, func(t *testing.T) {
				srv, _, _ := newTestSSHServer(t)
				// This test exercises concurrent connections, not the
				// intentionally unsynchronized recording audit fixture.
				srv.opts.AuditStore = nil
				srv.opts.LabMode = true
				if secretless {
					srv.opts.JWTSecret = nil
				}
				api := httptest.NewServer(revisionedSSHResetHandler(func(w http.ResponseWriter, r *http.Request) {
					initiator := r.Header.Get("X-Containd-SSH-Connection")
					if !secretless {
						claims := jwt.MapClaims{}
						_, err := jwt.ParseWithClaims(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), claims, func(*jwt.Token) (any, error) {
							return srv.opts.JWTSecret, nil
						})
						if err != nil {
							t.Error(err)
						}
						initiator, _ = claims["jti"].(string)
					}
					srv.RevokeConnections(initiator)
					warnings := []string{}
					if warning {
						warnings = append(warnings, "services: unavailable")
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"status": "reset", "loggedOut": true, "warnings": warnings})
				}))
				defer api.Close()
				srv.opts.BaseURL = api.URL
				addr := serveSSH(t, srv)
				dial := func() *ssh.Client {
					client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
						User: "containd", Auth: []ssh.AuthMethod{ssh.Password("containd")},
						HostKeyCallback: ssh.InsecureIgnoreHostKey(), // local ephemeral test server
						Timeout:         3 * time.Second,
					})
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = client.Close() })
					return client
				}
				other := dial()
				// Opening a channel ensures token issuance and registration
				// have completed before the initiating reset.
				idle, err := other.NewSession()
				if err != nil {
					t.Fatal(err)
				}
				defer idle.Close()
				client := dial()
				session, err := client.NewSession()
				if err != nil {
					t.Fatal(err)
				}
				defer session.Close()
				var output bytes.Buffer
				session.Stdout = &output
				session.Stdin = strings.NewReader("menu\n10\nNUCLEAR\nshow version\n")
				if err := session.Shell(); err != nil {
					t.Fatal(err)
				}
				exited := make(chan error, 1)
				go func() { exited <- session.Wait() }()
				select {
				case <-exited:
				case <-time.After(5 * time.Second):
					t.Fatal("reset did not log initiating SSH session out")
				}
				text := output.String()
				if warning {
					if !strings.Contains(text, "warning: services: unavailable") || strings.Contains(text, "Factory reset complete.") {
						t.Fatalf("untruthful warning output: %q", text)
					}
				} else if !strings.Contains(text, "Factory reset complete.") {
					t.Fatalf("result lost before disconnect: %q", text)
				}
				if strings.Count(text, "containd# ") != 1 {
					t.Fatalf("reset returned to REPL: %q", text)
				}
				otherExited := make(chan error, 1)
				go func() { otherExited <- other.Wait() }()
				select {
				case <-otherExited:
				case <-time.After(time.Second):
					t.Fatal("other SSH connection survived reset")
				}
			})
		}
	}
}
