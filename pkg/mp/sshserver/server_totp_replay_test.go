// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package sshserver

import (
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestSSHRefusesReusedTOTPCode(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "")
	srv, store, audits := newAssuranceServer(t)
	addr := serveSSH(t, srv)
	u, password := createAdmin(t, store, "replay-admin")
	secret := enrollTOTP(t, store, u.ID, u.Username)
	code := currentCode(t, secret)

	first := &scriptedKI{answers: [][]string{{code}}}
	client, err := dialSSH(addr, u.Username, nil, ssh.Password(password), first.method(1))
	if err != nil {
		t.Fatalf("first TOTP login: %v", err)
	}
	_ = client.Close()

	// The retry prompt says why the code was refused.
	replay := &scriptedKI{answers: [][]string{{code}, {code}}}
	if client, err := dialSSH(addr, u.Username, nil, ssh.Password(password), replay.method(2)); err == nil {
		_ = client.Close()
		t.Fatal("a reused TOTP code logged in")
	}
	if len(replay.prompts) != 2 || !strings.Contains(replay.prompts[1].instruction, "already used; wait for the next code") {
		t.Fatalf("prompts = %+v", replay.prompts)
	}
	if !audits.has("ssh.login", "denied", "totp code reused") {
		t.Fatalf("missing replay denial: %+v", audits.records)
	}
}
