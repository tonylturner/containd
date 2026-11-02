// SPDX-License-Identifier: Apache-2.0
package sshserver

import (
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestConfigureStaysInSSHCLI(t *testing.T) {
	srv, store, _ := newAssuranceServer(t)
	addr := serveSSH(t, srv)
	u, password := createAdmin(t, store, "configure-admin")
	client, err := dialSSH(addr, u.Username, nil, ssh.Password(password))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	output := runShell(t, client, "configure\nshow version\nexit\n")
	if !strings.Contains(output, "Already in configuration CLI") ||
		strings.Contains(output, "containd setup wizard") ||
		strings.Contains(output, "unknown command: configure") {
		t.Fatal(output)
	}
}
