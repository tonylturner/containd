// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package sshserver

import (
	"bufio"
	"bytes"
	"context"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/tonylturner/containd/pkg/cli"
)

func TestReadSecretInteractiveDoesNotEcho(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		want  string
		ok    bool
	}{
		{name: "plain", input: "s3cret\r", want: "s3cret", ok: true},
		{name: "backspace", input: "ab\x08c\x7fd\n", want: "ad", ok: true},
		{name: "backspace on empty", input: "\x7fx\n", want: "x", ok: true},
		{name: "control dropped", input: "a\x01b\n", want: "ab", ok: true},
		{name: "ctrl-c", input: "ab\x03", want: "\x03", ok: true},
		{name: "ctrl-d empty", input: "\x04", want: "", ok: false},
		{name: "eof", input: "abc", want: "", ok: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := &bytes.Buffer{}
			got, ok := readSecretInteractive(bufio.NewReader(strings.NewReader(tc.input)), out)
			if got != tc.want || ok != tc.ok {
				t.Fatalf("readSecretInteractive = %q, %v; want %q, %v", got, ok, tc.want, tc.ok)
			}
			wantOut := ""
			if strings.ContainsAny(tc.input, "\r\n") {
				wantOut = "\r\n"
			}
			if out.String() != wantOut {
				t.Fatalf("secret read wrote %q, want %q", out.String(), wantOut)
			}
		})
	}
}

func TestAskSecretWritesOnlyPromptAndNewline(t *testing.T) {
	srv, _, _ := newTestSSHServer(t)
	password := sshTestValue("hidden")
	session, rw := newTestSession(srv, cli.NewRegistry(nil, nil), password+"\n")
	got, ok := session.askSecret("Password: ")
	if !ok || got != password {
		t.Fatalf("askSecret = %q, %v", got, ok)
	}
	if rw.String() != "\rPassword: \r\n" {
		t.Fatalf("askSecret output = %q", rw.String())
	}

	cancel, cancelRW := newTestSession(srv, cli.NewRegistry(nil, nil), "ab\x03")
	if got, ok := cancel.askSecret("Password: "); ok || got != "" {
		t.Fatalf("ctrl-c askSecret = %q, %v", got, ok)
	}
	if cancelRW.String() != "\rPassword: ^C\r\n" {
		t.Fatalf("ctrl-c askSecret output = %q", cancelRW.String())
	}
}

func TestMenuResetPasswordHidesInputAndConfirms(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "")
	srv, store, audits := newTestSSHServer(t)
	password := sshTestValue("menu-hidden")
	session, rw := newTestSession(srv, cli.NewRegistry(nil, nil), "containd\n"+password+"\n"+password+"\n")
	session.menuResetPassword()

	got := rw.String()
	if strings.Contains(got, password) {
		t.Fatalf("password echoed: %q", got)
	}
	if !strings.Contains(got, "Confirm new password: ") || !strings.Contains(got, "Password updated.") {
		t.Fatalf("missing confirmation or success: %q", got)
	}
	admin, err := store.GetByUsername(context.Background(), "containd")
	if err != nil {
		t.Fatal(err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(password)); err != nil {
		t.Fatalf("password was not updated: %v", err)
	}
	if len(audits.records) != 1 || audits.records[0].Action != "auth.password.change" {
		t.Fatalf("audit: %+v", audits.records)
	}
}

func TestPasswordMismatchRefuses(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "")
	first, second := sshTestValue("first"), sshTestValue("second")
	for _, flow := range []string{"menu", "wizard"} {
		t.Run(flow, func(t *testing.T) {
			srv, store, audits := newTestSSHServer(t)
			before, err := store.GetByUsername(context.Background(), "containd")
			if err != nil {
				t.Fatal(err)
			}
			session, rw := newTestSession(srv, cli.NewRegistry(nil, nil), "containd\n"+first+"\n"+second+"\n")
			if flow == "menu" {
				session.menuResetPassword()
			} else if session.wizardPromptPassword() {
				t.Fatal("wizard continued after a password mismatch")
			}

			got := rw.String()
			if strings.Contains(got, first) || strings.Contains(got, second) {
				t.Fatalf("password echoed: %q", got)
			}
			if !strings.Contains(got, "error: passwords do not match") {
				t.Fatalf("missing mismatch error: %q", got)
			}
			if strings.Contains(strings.ToLower(got), "password updated") {
				t.Fatalf("mismatch reported success: %q", got)
			}
			if len(audits.records) != 0 {
				t.Fatalf("unexpected audit records: %+v", audits.records)
			}
			after, err := store.GetByUsername(context.Background(), "containd")
			if err != nil {
				t.Fatal(err)
			}
			if after.PasswordHash != before.PasswordHash {
				t.Fatal("mismatch changed credentials")
			}
		})
	}
}

func TestPasswordPromptBlankSkipsConfirmation(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "")
	srv, _, audits := newTestSSHServer(t)
	session, rw := newTestSession(srv, cli.NewRegistry(nil, nil), "  \n")
	session.menuResetPassword()
	got := rw.String()
	if !strings.Contains(got, "Cancelled.") || strings.Contains(got, "New password") {
		t.Fatalf("blank entry did not cancel before confirmation: %q", got)
	}
	if len(audits.records) != 0 {
		t.Fatalf("unexpected audit records: %+v", audits.records)
	}
}
