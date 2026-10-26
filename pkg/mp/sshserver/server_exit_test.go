// SPDX-License-Identifier: Apache-2.0
package sshserver

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// An exec request reports its command's exit status: 0 on success, 1 when
// the command fails or is empty. The appliance shell reports 0 when it
// closes.
func TestSessionsSendExitStatus(t *testing.T) {
	srv, store, _ := newAssuranceServer(t)
	srv.opts.APIClient = newSSHTestHTTPClient()
	addr := serveSSH(t, srv)
	u, password := createAdmin(t, store, "exit-admin")
	client, err := dialSSH(addr, u.Username, nil, ssh.Password(password))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer client.Close()

	for _, tc := range []struct {
		command string
		status  int
		output  string
	}{
		{"show health", 0, "ok"},
		{"no-such-command", 1, ""},
		{"   ", 1, "no command given"},
	} {
		session, err := client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		out, err := session.CombinedOutput(tc.command)
		_ = session.Close()
		status := 0
		var exit *ssh.ExitError
		if errors.As(err, &exit) {
			status = exit.ExitStatus()
		} else if err != nil {
			t.Fatalf("%q: %v: %s", tc.command, err, out)
		}
		if status != tc.status || !strings.Contains(string(out), tc.output) {
			t.Fatalf("%q exited %d with %q, want %d with %q", tc.command, status, out, tc.status, tc.output)
		}
	}

	if out := runShell(t, client, "exit\n"); !strings.Contains(out, "containd# ") {
		t.Fatalf("CLI did not open: %q", out)
	}
}
