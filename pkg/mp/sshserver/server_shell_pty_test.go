// SPDX-License-Identifier: Apache-2.0
package sshserver

import (
	"bytes"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

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

// With a client PTY, shell in the appliance CLI opens the Linux shell, and the
// CLI reads the next line after that shell exits.
func TestShellCommandWithPTYOpensLinuxShell(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("needs /bin/bash")
	}
	srv, store, _ := newAssuranceServer(t)
	addr := serveSSH(t, srv)
	u, password := createAdmin(t, store, "pty-shell-admin")
	client, err := dialSSH(addr, u.Username, nil, ssh.Password(password))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer client.Close()
	tty := openTTY(t, client)
	tty.waitFor(t, "containd# ", 1)
	tty.send(t, "shell\n")
	tty.waitFor(t, "shell\r\n", 1)
	tty.send(t, "echo marker-$((6*7))\n")
	tty.waitFor(t, "marker-42", 1)
	tty.send(t, "exit\n")
	tty.waitFor(t, "containd# ", 2)
	tty.send(t, "exit\n")
	if err := tty.session.Wait(); err != nil {
		t.Fatalf("CLI did not exit: %v: %q", err, tty.output())
	}
}

// tty is an interactive SSH session with a PTY.
type tty struct {
	session *ssh.Session
	stdin   io.WriteCloser
	mu      sync.Mutex
	out     bytes.Buffer
	wrote   chan struct{}
}

func openTTY(t *testing.T, client *ssh.Client) *tty {
	t.Helper()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	if err := session.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	tt := &tty{session: session, wrote: make(chan struct{}, 1)}
	session.Stdout = tt
	session.Stderr = tt
	if tt.stdin, err = session.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	if err := session.Shell(); err != nil {
		t.Fatal(err)
	}
	return tt
}

func (tt *tty) Write(p []byte) (int, error) {
	tt.mu.Lock()
	defer tt.mu.Unlock()
	select {
	case tt.wrote <- struct{}{}:
	default:
	}
	return tt.out.Write(p)
}

func (tt *tty) output() string {
	tt.mu.Lock()
	defer tt.mu.Unlock()
	return tt.out.String()
}

func (tt *tty) send(t *testing.T, s string) {
	t.Helper()
	if _, err := io.WriteString(tt.stdin, s); err != nil {
		t.Fatal(err)
	}
}

// waitFor waits until the output holds n occurrences of s.
func (tt *tty) waitFor(t *testing.T, s string, n int) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for strings.Count(tt.output(), s) < n {
		select {
		case <-tt.wrote:
		case <-deadline:
			t.Fatalf("no %q (x%d) in %q", s, n, tt.output())
		}
	}
}
