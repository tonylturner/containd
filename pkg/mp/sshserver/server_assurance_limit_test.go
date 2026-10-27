// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package sshserver

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/ssh"

	"github.com/tonylturner/containd/pkg/cp/users"
)

// wrongTOTPCode returns a code that no step in the window around now accepts.
func wrongTOTPCode(t *testing.T, secret string, now time.Time) string {
	t.Helper()
	valid := map[string]bool{}
	for _, d := range []time.Duration{-users.TOTPPeriod, 0, users.TOTPPeriod} {
		code, err := totp.GenerateCode(secret, now.Add(d*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		valid[code] = true
	}
	for _, candidate := range []string{"000000", "111111", "222222", "333333"} {
		if !valid[candidate] {
			return candidate
		}
	}
	t.Fatal("no wrong code found")
	return ""
}

func (s *syncAuditStore) count(action, detail string) int {
	records, _ := s.List(context.Background(), 0)
	n := 0
	for _, r := range records {
		if r.Action == action && r.Result == "denied" && r.Detail == detail {
			n++
		}
	}
	return n
}

// Wrong codes from other clients lock the account's TOTP check for SSH too.
// The lock is recorded once, and the prompt says why the code was refused.
func TestSSHTOTPLockIsPerAccount(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "")
	srv, store, audits := newAssuranceServer(t)
	addr := serveSSH(t, srv)
	u, password := createAdmin(t, store, "locked-admin")
	secret := enrollTOTP(t, store, u.ID, u.Username)
	for i := 0; i < users.LimitFor(users.FactorTOTP).MaxFailures; i++ {
		now := time.Now()
		if err := store.AcceptTOTP(context.Background(), u.ID, wrongTOTPCode(t, secret, now), now); err == nil {
			t.Fatal("wrong code accepted")
		}
	}

	for attempt := 0; attempt < 2; attempt++ {
		ki := &scriptedKI{answers: [][]string{{currentCode(t, secret)}, {currentCode(t, secret)}}}
		if client, err := dialSSH(addr, u.Username, nil, ssh.Password(password), ki.method(2)); err == nil {
			_ = client.Close()
			t.Fatal("a locked TOTP check logged in")
		}
		if len(ki.prompts) != 2 || !strings.Contains(ki.prompts[1].instruction, "too many failed authentication codes for this account") {
			t.Fatalf("prompts = %+v", ki.prompts)
		}
	}
	if n := audits.count("ssh.login", "totp locked after repeated failures"); n != 1 {
		t.Fatalf("lock records = %d: %+v", n, audits.records)
	}
	if n := audits.count("ssh.login", "invalid totp code"); n != 0 {
		t.Fatalf("locked attempts were checked: %+v", audits.records)
	}
}

// A key login's forced change shares the account's current-password limit.
func TestSSHKeyLoginForcedChangeUsesCurrentPasswordLimit(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "")
	srv, store, audits := newAssuranceServer(t)
	addr := serveSSH(t, srv)
	signer, line := clientKey(t)
	if err := srv.SeedAuthorizedKey("containd", line); err != nil {
		t.Fatal(err)
	}
	admin, err := store.GetByUsername(context.Background(), "containd")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < users.LimitFor(users.FactorCurrentPassword).MaxFailures; i++ {
		if err := store.CheckCurrentPassword(context.Background(), admin.ID, "wrong", time.Now()); err == nil {
			t.Fatal("wrong current password accepted")
		}
	}
	fresh := sshTestValue("key-locked")
	for attempt := 0; attempt < 2; attempt++ {
		ki := &scriptedKI{answers: [][]string{{"containd", fresh, fresh}}}
		if client, err := dialSSH(addr, "containd", nil, ssh.PublicKeys(signer), ki.method(1)); err == nil {
			_ = client.Close()
			t.Fatal("a locked current-password check changed the password")
		}
	}
	if n := audits.count("ssh.login", "current password locked after repeated failures"); n != 1 {
		t.Fatalf("lock records = %d: %+v", n, audits.records)
	}
	after, err := store.GetByUsername(context.Background(), "containd")
	if err != nil || after.PasswordHash != admin.PasswordHash || !after.MustChangePassword {
		t.Fatalf("locked check changed the account: %+v, %v", after, err)
	}
}
