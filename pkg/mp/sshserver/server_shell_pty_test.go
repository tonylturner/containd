// SPDX-License-Identifier: Apache-2.0
package sshserver

import (
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Without a client PTY, shell and bash in the appliance CLI refuse, start no
// Linux shell and leave the CLI running, in both shell modes.
func TestShellCommandNeedsPTY(t *testing.T) {
	for _, mode := range []string{"appliance", "linux"} {
		t.Run(mode, func(t *testing.T) {
			srv, store, _ := newAssuranceServer(t)
			srv.opts.ShellMode = mode
			addr := serveSSH(t, srv)
			u, password := createAdmin(t, store, "pty-"+mode)
			client, err := dialSSH(addr, u.Username, nil, ssh.Password(password))
			if err != nil {
				t.Fatalf("login: %v", err)
			}
			defer client.Close()

			out := runShell(t, client, "shell\necho marker-$((6*7))\nbash\nexit\n")
			if got := strings.Count(out, "The Linux shell needs a terminal"); got != 2 {
				t.Fatalf("refusals = %d, want 2: %q", got, out)
			}
			if strings.Contains(out, "marker-42") {
				t.Fatalf("a Linux shell ran without a PTY: %q", out)
			}
			if got := strings.Count(out, "containd# "); got < 4 {
				t.Fatalf("CLI stopped after a refusal: %q", out)
			}
		})
	}
}
