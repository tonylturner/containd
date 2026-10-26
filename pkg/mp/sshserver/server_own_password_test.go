// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package sshserver

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cli"
	"github.com/tonylturner/containd/pkg/cp/users"
)

// Wrong current passwords from any path lock the console's own change; the
// lock is recorded once.
func TestOwnPasswordChangeUsesCurrentPasswordLimit(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "")
	srv, store, audits := newTestSSHServer(t)
	before, err := store.GetByUsername(context.Background(), "containd")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < users.LimitFor(users.FactorCurrentPassword).MaxFailures; i++ {
		if err := store.CheckCurrentPassword(context.Background(), before.ID, "wrong", time.Now()); err == nil {
			t.Fatal("wrong current password accepted")
		}
	}
	fresh := sshTestValue("own-locked")
	for attempt := 0; attempt < 2; attempt++ {
		session, rw := newTestSession(srv, cli.NewRegistry(nil, nil), "containd\n"+fresh+"\n"+fresh+"\n")
		session.menuResetPassword()
		got := rw.String()
		if !strings.Contains(got, "error: too many failed current password attempts for this account") || strings.Contains(got, "New password") {
			t.Fatalf("locked change output: %q", got)
		}
	}
	if len(audits.records) != 1 || audits.records[0].Result != "denied" ||
		audits.records[0].Detail != "ssh menu: current password locked after repeated failures" {
		t.Fatalf("audit records = %+v", audits.records)
	}
	after, err := store.GetByUsername(context.Background(), "containd")
	if err != nil || after.PasswordHash != before.PasswordHash {
		t.Fatalf("locked check changed the password: %v", err)
	}
}
