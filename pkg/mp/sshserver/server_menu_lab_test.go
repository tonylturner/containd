// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package sshserver

import (
	"context"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cli"
	"github.com/tonylturner/containd/pkg/cp/users"
)

func TestLabModeMenuRefusesPasswordReset(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "1")
	srv, store, audits := newTestSSHServer(t)
	before, err := store.GetByUsername(context.Background(), "containd")
	if err != nil {
		t.Fatal(err)
	}

	session, output := newTestSession(srv, cli.NewRegistry(nil, nil), sshTestValue("lab-menu")+"\n")
	session.menuResetPassword()

	got := output.String()
	if !strings.Contains(got, "error: "+users.ErrPasswordChangeLabMode.Error()) {
		t.Fatalf("missing lab-mode refusal: %q", got)
	}
	if strings.Contains(got, "New password") || strings.Contains(got, "Password updated.") {
		t.Fatalf("menu prompted for or reported a password change: %q", got)
	}
	if len(audits.records) != 0 {
		t.Fatalf("unexpected audit records: %+v", audits.records)
	}
	after, err := store.GetByUsername(context.Background(), "containd")
	if err != nil {
		t.Fatal(err)
	}
	if after.PasswordHash != before.PasswordHash {
		t.Fatal("refused reset changed credentials")
	}
}

func TestLabModeWizardSkipsPasswordStep(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "1")
	srv, store, audits := newTestSSHServer(t)
	before, err := store.GetByUsername(context.Background(), "containd")
	if err != nil {
		t.Fatal(err)
	}
	reg := cli.NewRegistry(nil, &cli.API{BaseURL: "http://127.0.0.1:8080", Client: newSSHTestHTTPClient()})

	// One answer per remaining prompt: four settings, SSH password auth,
	// SSH key, outbound quick start, then "no" to commit.
	session, output := newTestSession(srv, reg, "\n\n\n\n\n\n\nno\n")
	session.runWizardFlow()

	got := output.String()
	if !strings.Contains(got, "password step skipped: "+users.ErrPasswordChangeLabMode.Error()) {
		t.Fatalf("missing lab-mode skip notice: %q", got)
	}
	if strings.Contains(got, "Set a new password") {
		t.Fatalf("wizard prompted for a password in lab mode: %q", got)
	}
	for _, later := range []string{"Paste an SSH public key", "Enable outbound Internet", "Not committed."} {
		if !strings.Contains(got, later) {
			t.Fatalf("wizard stopped before %q: %q", later, got)
		}
	}
	if len(audits.records) != 0 {
		t.Fatalf("unexpected audit records: %+v", audits.records)
	}
	after, err := store.GetByUsername(context.Background(), "containd")
	if err != nil {
		t.Fatal(err)
	}
	if after.PasswordHash != before.PasswordHash {
		t.Fatal("wizard changed credentials in lab mode")
	}
}
