// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package sshserver

import (
	"context"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/tonylturner/containd/pkg/cli"
)

// The menu and wizard change the logged-in account's own password, so they
// confirm the current one first, as the web change does.
func TestOwnPasswordChangeRequiresCurrentPassword(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "")
	fresh := sshTestValue("own-change")
	for flow, path := range map[string]string{"menu": "ssh menu", "wizard": "ssh setup wizard"} {
		t.Run(flow, func(t *testing.T) {
			srv, store, audits := newTestSSHServer(t)
			before, err := store.GetByUsername(context.Background(), "containd")
			if err != nil {
				t.Fatal(err)
			}
			run := func(input string) (string, bool) {
				session, rw := newTestSession(srv, cli.NewRegistry(nil, nil), input)
				if flow == "menu" {
					session.menuResetPassword()
					return rw.String(), true
				}
				ok := session.wizardPromptPassword()
				return rw.String(), ok
			}

			wrong := sshTestValue("not-current")
			got, ok := run(wrong + "\n" + fresh + "\n" + fresh + "\n")
			if strings.Contains(got, wrong) || !strings.Contains(got, "Current password") || !strings.Contains(got, "error: current password invalid") {
				t.Fatalf("wrong current password output: %q", got)
			}
			if strings.Contains(got, "New password") || strings.Contains(strings.ToLower(got), "password updated") {
				t.Fatalf("wrong current password reached the change: %q", got)
			}
			if flow == "wizard" && ok {
				t.Fatal("wizard continued after a wrong current password")
			}
			after, err := store.GetByUsername(context.Background(), "containd")
			if err != nil {
				t.Fatal(err)
			}
			if after.PasswordHash != before.PasswordHash {
				t.Fatal("wrong current password changed credentials")
			}
			if len(audits.records) != 1 {
				t.Fatalf("audit records = %+v", audits.records)
			}
			denied := audits.records[0]
			if denied.Action != "auth.password.change" || denied.Result != "denied" || denied.Actor != "containd" ||
				denied.Detail != path+": current password invalid" || strings.Contains(denied.Detail, wrong) {
				t.Fatalf("denied record = %+v", denied)
			}

			got, ok = run("containd\n" + fresh + "\n" + fresh + "\n")
			if !ok || strings.Contains(got, fresh) || !strings.Contains(strings.ToLower(got), "password updated") {
				t.Fatalf("change with the current password: ok=%v %q", ok, got)
			}
			after, err = store.GetByUsername(context.Background(), "containd")
			if err != nil {
				t.Fatal(err)
			}
			if bcrypt.CompareHashAndPassword([]byte(after.PasswordHash), []byte(fresh)) != nil {
				t.Fatal("password was not updated")
			}
			if len(audits.records) != 2 || audits.records[1].Result != "success" || audits.records[1].Detail != path {
				t.Fatalf("audit records = %+v", audits.records)
			}
		})
	}
}
