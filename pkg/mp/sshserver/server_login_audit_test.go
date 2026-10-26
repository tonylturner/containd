// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package sshserver

import (
	"context"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/tonylturner/containd/pkg/common/ratelimit"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/users"
)

// loginDenials returns the ssh.login denied records written so far.
func loginDenials(audits *syncAuditStore) []audit.Record {
	records, _ := audits.List(context.Background(), 0)
	var out []audit.Record
	for _, r := range records {
		if r.Action == "ssh.login" && r.Result == "denied" {
			out = append(out, r)
		}
	}
	return out
}

// waitForDenials polls until n denial records exist: a refused key is
// recorded when the server ends the unauthenticated connection, which can be
// after the client has already returned.
func waitForDenials(t *testing.T, audits *syncAuditStore, n int) []audit.Record {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		got := loginDenials(audits)
		if len(got) >= n || time.Now().After(deadline) {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSSHFailedLoginsAreAudited(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "")
	srv, store, audits := newAssuranceServer(t)
	addr := serveSSH(t, srv)
	u, password := createAdmin(t, store, "audit-admin")
	viewer := sshTestValue("viewer")
	if _, err := store.Create(context.Background(), users.User{Username: "audit-viewer", Role: "view"}, viewer); err != nil {
		t.Fatal(err)
	}
	wrong := sshTestValue("wrong")

	attempts := []struct {
		user, password, detail string
	}{
		{u.Username, wrong, "invalid password"},
		{"no-such-user", wrong, "unknown user"},
		{"audit-viewer", viewer, "not an admin"},
	}
	for i, a := range attempts {
		if client, err := dialSSH(addr, a.user, nil, ssh.Password(a.password)); err == nil {
			_ = client.Close()
			t.Fatalf("%s logged in", a.user)
		}
		got := loginDenials(audits)
		if len(got) != i+1 {
			t.Fatalf("after %s: denials = %+v", a.detail, got)
		}
		r := got[i]
		if r.Actor != a.user || r.Detail != a.detail || r.Source != "ssh" || !strings.HasPrefix(r.Target, "127.0.0.1:") {
			t.Fatalf("denial record = %+v, want actor %q detail %q", r, a.user, a.detail)
		}
	}

	// A refused key is one record per connection, naming the key.
	signer, _ := clientKey(t)
	if client, err := dialSSH(addr, u.Username, nil, ssh.PublicKeys(signer)); err == nil {
		_ = client.Close()
		t.Fatal("unauthorized key logged in")
	}
	got := waitForDenials(t, audits, len(attempts)+1)
	if len(got) != len(attempts)+1 {
		t.Fatalf("key refusal not audited: %+v", got)
	}
	keyRecord := got[len(attempts)]
	if keyRecord.Actor != u.Username || keyRecord.Detail != "public key not authorized: "+ssh.FingerprintSHA256(signer.PublicKey()) {
		t.Fatalf("key denial record = %+v", keyRecord)
	}

	// A key refused before a successful password login is not a failed login.
	client, err := dialSSH(addr, u.Username, nil, ssh.PublicKeys(signer), ssh.Password(password))
	if err != nil {
		t.Fatalf("password after refused key: %v", err)
	}
	_ = client.Close()

	records, _ := audits.List(context.Background(), 0)
	for _, r := range records {
		if strings.Contains(r.Detail, wrong) || strings.Contains(r.Detail, password) || strings.Contains(r.Detail, viewer) {
			t.Fatalf("audit record holds a password: %+v", r)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if n := len(loginDenials(audits)); n != len(attempts)+1 {
		t.Fatalf("successful login wrote denials: %+v", loginDenials(audits))
	}
}

func TestSSHRateLimitedAttemptsAreNotAudited(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "")
	srv, store, audits := newAssuranceServer(t)
	srv.pwLimiter = ratelimit.NewAttemptLimiter(time.Minute, 2, time.Minute)
	addr := serveSSH(t, srv)
	u, password := createAdmin(t, store, "limited-admin")
	signer, line := clientKey(t)
	if err := srv.SeedAuthorizedKey(u.Username, line); err != nil {
		t.Fatal(err)
	}
	wrong := sshTestValue("wrong")
	for i := 0; i < 2; i++ {
		if client, err := dialSSH(addr, u.Username, nil, ssh.Password(wrong)); err == nil {
			_ = client.Close()
			t.Fatal("wrong password logged in")
		}
	}
	// Blocked attempts are refused before any check and write nothing, so the
	// limiter bounds the record volume. Keys share the same limit.
	for name, method := range map[string]ssh.AuthMethod{"password": ssh.Password(password), "key": ssh.PublicKeys(signer)} {
		if client, err := dialSSH(addr, u.Username, nil, method); err == nil {
			_ = client.Close()
			t.Fatalf("blocked %s login succeeded", name)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if got := loginDenials(audits); len(got) != 2 {
		t.Fatalf("denials = %+v, want the 2 checked attempts", got)
	}
}

func TestSSHLabModeFailedLoginsUnchanged(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "1")
	srv, _, audits := newAssuranceServer(t)
	srv.opts.LabMode = true
	srv.pwLimiter = ratelimit.NewAttemptLimiter(time.Minute, 2, time.Minute)
	addr := serveSSH(t, srv)
	signer, line := clientKey(t)
	if err := srv.SeedAuthorizedKey("containd", line); err != nil {
		t.Fatal(err)
	}
	stranger, _ := clientKey(t)
	for i := 0; i < 3; i++ {
		if client, err := dialSSH(addr, "containd", nil, ssh.Password("wrong")); err == nil {
			_ = client.Close()
			t.Fatal("wrong password logged in")
		}
		if client, err := dialSSH(addr, "containd", nil, ssh.PublicKeys(stranger)); err == nil {
			_ = client.Close()
			t.Fatal("unauthorized key logged in")
		}
	}
	// Lab-mode key logins stay outside the password limiter.
	client, err := dialSSH(addr, "containd", nil, ssh.PublicKeys(signer))
	if err != nil {
		t.Fatalf("lab key login after password failures: %v", err)
	}
	_ = client.Close()
	time.Sleep(100 * time.Millisecond)
	if got := loginDenials(audits); len(got) != 0 {
		t.Fatalf("lab mode wrote denials: %+v", got)
	}
}
