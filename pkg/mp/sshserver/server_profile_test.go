// SPDX-License-Identifier: Apache-2.0

package sshserver

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/tonylturner/containd/pkg/common/profile"
	"github.com/tonylturner/containd/pkg/cp/users"
)

func TestStrictShellHelpBootstrap(t *testing.T) {
	if os.Getenv("CONTAIND_TEST_STRICT_SSH") != "1" {
		t.Setenv(profile.EnvVar, "strict")
		t.Setenv("CONTAIND_TEST_STRICT_SSH", "1")
		cmd := exec.Command(os.Args[0], "-test.run=^TestStrictShellHelpBootstrap$", "-test.v")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("strict subprocess: %v\n%s", err, output)
		}
		t.Log(string(output))
		return
	}
	t.Setenv("CONTAIND_LAB_MODE", "")
	t.Setenv("CONTAIND_DEFAULT_ADMIN_USERNAME", "")
	t.Setenv("CONTAIND_DEFAULT_ADMIN_PASSWORD", "")
	if _, err := profile.Load(); err != nil || !profile.IsStrict() {
		t.Fatalf("strict profile: %v", err)
	}
	t.Run("shell and help", func(t *testing.T) {
		srv, store, _ := newAssuranceServer(t)
		srv.opts.ShellMode = "linux" // A carried saved mode cannot select bash.
		if srv.isLinuxShellMode() {
			t.Fatal("strict selected the Linux shell")
		}
		u, password := createAdmin(t, store, "strict-shell-admin")
		addr := serveSSH(t, srv)
		client, err := dialSSH(addr, u.Username, nil, ssh.Password(password))
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		out := runShell(t, client, "help\nshell\nexit\n")
		if !strings.Contains(out, "CONTAIND_PROFILE=strict refuses shell: the Linux shell is training-only") {
			t.Fatalf("missing refusal: %q", out)
		}
		for _, absent := range []string{"shell opens", "Entering Linux OS shell", "falling back", "needs a terminal"} {
			if strings.Contains(out, absent) {
				t.Fatalf("unexpected %q: %q", absent, out)
			}
		}
		if !strings.Contains(out, "menu, wizard, diagnostics") {
			t.Fatalf("missing SSH help: %q", out)
		}
		tty := openTTY(t, client)
		tty.waitFor(t, "containd(config", 1)
		tty.send(t, "shell\n")
		tty.waitFor(t, "CONTAIND_PROFILE=strict refuses shell", 1)
		tty.send(t, "exit\n")
		if err := tty.session.Wait(); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(tty.output(), "Entering Linux OS shell") {
			t.Fatal("PTY bypassed strict shell refusal")
		}
	})
	for _, keyLogin := range []bool{false, true} {
		name := "password"
		if keyLogin {
			name = "bootstrap key"
		}
		t.Run(name, func(t *testing.T) {
			srv, store, audits := newAssuranceServer(t)
			// Model the account state issued by bootstrap, without depending on
			// password generation or delivery (owned by the users store).
			oneTime := sshTestValue("one-time")
			u, err := store.Create(context.Background(), users.User{
				Username: "pending-admin", Role: "admin", MustChangePassword: true,
			}, oneTime)
			if err != nil {
				t.Fatal(err)
			}
			method := ssh.Password(oneTime)
			if keyLogin {
				signer, line := clientKey(t)
				if err := srv.SeedAuthorizedKey(u.Username, line); err != nil {
					t.Fatal(err)
				}
				srv.opts.AllowPassword = false
				method = ssh.PublicKeys(signer)
			}
			addr := serveSSH(t, srv)
			if client, err := dialSSH(addr, u.Username, nil, method); err == nil {
				_ = client.Close()
				t.Fatal("first factor bypassed forced password change")
			}
			fresh := sshTestValue("strict-changed")
			answers := []string{fresh, fresh}
			if keyLogin {
				answers = append([]string{oneTime}, answers...)
			}
			ki := &scriptedKI{answers: [][]string{answers}}
			client, err := dialSSH(addr, u.Username, nil, method, ki.method(1))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if len(ki.prompts) != 1 || len(ki.prompts[0].questions) != len(answers) {
				t.Fatalf("forced-change prompts: %+v", ki.prompts)
			}
			if out := runShell(t, client, "exit\n"); !strings.Contains(out, "containd(config") {
				t.Fatalf("no appliance CLI after change: %q", out)
			}
			changed, err := store.GetByID(context.Background(), u.ID)
			if err != nil || changed.MustChangePassword {
				t.Fatalf("pending account after change: %+v, %v", changed, err)
			}
			if !audits.has("auth.password.change", "success", "forced change at ssh login") {
				t.Fatal("missing forced-change audit")
			}
		})
	}
}
