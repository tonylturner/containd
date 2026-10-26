// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package sshserver

import (
	"context"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/tonylturner/containd/pkg/common/ratelimit"
	"github.com/tonylturner/containd/pkg/cp/users"
)

// A factor lock writes one record, but every refusal it causes counts against
// the client's login limit, so retrying a locked check still blocks the client.
func TestSSHUnrecordedLockRefusalsCountAgainstClientLimit(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "")
	srv, store, audits := newAssuranceServer(t)
	srv.pwLimiter = ratelimit.NewAttemptLimiter(time.Minute, 2, time.Minute)
	addr := serveSSH(t, srv)
	u, password := createAdmin(t, store, "lock-limit-admin")
	secret := enrollTOTP(t, store, u.ID, u.Username)
	for i := 0; i < users.LimitFor(users.FactorTOTP).MaxFailures; i++ {
		now := time.Now()
		if err := store.AcceptTOTP(context.Background(), u.ID, wrongTOTPCode(t, secret, now), now); err == nil {
			t.Fatal("wrong code accepted")
		}
	}

	locked := &scriptedKI{answers: [][]string{{currentCode(t, secret)}, {currentCode(t, secret)}}}
	if client, err := dialSSH(addr, u.Username, nil, ssh.Password(password), locked.method(2)); err == nil {
		_ = client.Close()
		t.Fatal("a locked TOTP check logged in")
	}
	if len(locked.prompts) != 2 {
		t.Fatalf("prompts = %+v", locked.prompts)
	}
	if n := audits.count("ssh.login", "totp locked after repeated failures"); n != 1 {
		t.Fatalf("lock records = %d: %+v", n, audits.records)
	}

	// The recorded and the unrecorded refusal exhaust the limit, which refuses
	// the right password before the TOTP prompt.
	blocked := &scriptedKI{answers: [][]string{{currentCode(t, secret)}}}
	if client, err := dialSSH(addr, u.Username, nil, ssh.Password(password), blocked.method(1)); err == nil {
		_ = client.Close()
		t.Fatal("rate-limited account logged in")
	}
	if len(blocked.prompts) != 0 {
		t.Fatalf("blocked client was prompted: %+v", blocked.prompts)
	}
}
