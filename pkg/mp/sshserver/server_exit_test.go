// SPDX-License-Identifier: Apache-2.0
package sshserver

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
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

// A Linux shell reports its exit status when it exits, and exit-signal with
// the RFC 4254 signal name when a signal kills it; a signal outside that
// list is named SIG@openssh.com, as OpenSSH names it.
func TestLinuxShellSendsExitSignal(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("the Linux shell test kills /bin/bash")
	}
	srv, store, _ := newAssuranceServer(t)
	srv.opts.ShellMode = "linux"
	addr := serveSSH(t, srv)
	u, password := createAdmin(t, store, "linux-shell-admin")
	client, err := dialSSH(addr, u.Username, nil, ssh.Password(password))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer client.Close()

	for _, tc := range []struct {
		input, signal string
		status        int
		msg           string
	}{
		{"exit 3\n", "", 3, ""},
		{"kill -KILL $$\n", "KILL", 128 + 9, "shell killed by signal 9 (killed)"},
		{"kill -USR1 $$\n", "USR1", 128, "shell killed by signal " + strconv.Itoa(int(syscall.SIGUSR1)) + " (user defined signal 1)"},
		{"kill -VTALRM $$\n", "SIG@openssh.com", 128, "shell killed by signal " + strconv.Itoa(int(syscall.SIGVTALRM)) + " (virtual timer expired)"},
	} {
		session, err := client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		if err := session.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
			t.Fatal(err)
		}
		session.Stdin = strings.NewReader(tc.input)
		if err := session.Shell(); err != nil {
			t.Fatal(err)
		}
		err = session.Wait()
		_ = session.Close()
		var exit *ssh.ExitError
		if !errors.As(err, &exit) {
			t.Fatalf("%q: %v", tc.input, err)
		}
		if exit.Signal() != tc.signal || exit.ExitStatus() != tc.status || exit.Msg() != tc.msg || (tc.signal != "" && exit.Lang() != "en") {
			t.Fatalf("%q: signal %q status %d msg %q lang %q; want signal %q status %d msg %q",
				tc.input, exit.Signal(), exit.ExitStatus(), exit.Msg(), exit.Lang(), tc.signal, tc.status, tc.msg)
		}
	}
}
