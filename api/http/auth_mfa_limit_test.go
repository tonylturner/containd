// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/users"
)

// doFrom sends a request from the client address addr.
func (f accountFixture) doFrom(t *testing.T, addr, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := jwtAuthedRequest(method, path, bytes.NewBuffer(raw), token)
	req.RemoteAddr = addr + ":40000"
	rec := httptest.NewRecorder()
	f.server.ServeHTTP(rec, req)
	return rec
}

// mfaLoginFrom signs in the fixture admin from addr and returns the code step.
func mfaLoginFrom(t *testing.T, f accountFixture, addr, code string) *httptest.ResponseRecorder {
	t.Helper()
	rec := f.doFrom(t, addr, http.MethodPost, "/api/v1/auth/login", "", map[string]string{"username": "acct-admin", "password": testPassword})
	var challenge mfaLoginChallengeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &challenge); rec.Code != http.StatusOK || err != nil || challenge.MFAChallengeToken == "" {
		t.Fatalf("login challenge from %s = %d %s", addr, rec.Code, rec.Body)
	}
	return f.doFrom(t, addr, http.MethodPost, "/api/v1/auth/login/mfa", "", map[string]string{"challengeToken": challenge.MFAChallengeToken, "code": code})
}

func requireLockRefusal(t *testing.T, rec *httptest.ResponseRecorder, message string) {
	t.Helper()
	if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), message) {
		t.Fatalf("locked check = %d %s", rec.Code, rec.Body)
	}
	if retry, err := strconv.Atoi(rec.Header().Get("Retry-After")); err != nil || retry <= 0 {
		t.Fatalf("Retry-After = %q", rec.Header().Get("Retry-After"))
	}
}

func countDenied(t *testing.T, f accountFixture, detail string) int {
	t.Helper()
	records, err := f.audits.List(context.Background(), 500)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range records {
		if r.Result == "denied" && r.Detail == detail {
			n++
		}
	}
	return n
}

// Wrong codes from many client addresses lock the account's code check, not
// its password login, and the lock is recorded once.
func TestMFACodeGuessesAreLimitedPerAccount(t *testing.T) {
	f := newAccountFixture(t)
	secret := enrollFixtureTOTP(t, f)
	limit := users.LimitFor(users.FactorTOTP)
	for i := 0; i < limit.MaxFailures; i++ {
		if rec := mfaLoginFrom(t, f, fmt.Sprintf("192.0.2.%d", i+1), "000000"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("wrong code %d = %d %s", i, rec.Code, rec.Body)
		}
	}
	const locked = "too many failed authentication codes"
	requireLockRefusal(t, mfaLoginFrom(t, f, "198.51.100.1", fixtureCode(t, secret)), locked)
	requireLockRefusal(t, mfaLoginFrom(t, f, "198.51.100.2", fixtureCode(t, secret)), locked)

	// MFA self-disable checks the same code.
	token, _ := f.session(t, f.adminID)
	requireLockRefusal(t, f.doFrom(t, "198.51.100.3", http.MethodPost, "/api/v1/auth/me/mfa/disable", token, map[string]string{"currentPassword": testPassword, "code": fixtureCode(t, secret)}), locked)
	if n := countDenied(t, f, "totp locked after repeated failures"); n != 1 {
		t.Fatalf("lock records = %d, want 1", n)
	}
	requireAuditDetail(t, f, "auth.login", "totp locked after repeated failures")

	// The password step is not locked: a wrong password is still refused as
	// one, and the right one still reaches the code step.
	if rec := f.doFrom(t, "203.0.113.1", http.MethodPost, "/api/v1/auth/login", "", map[string]string{"username": "acct-admin", "password": "wrong"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password while the code is locked = %d %s", rec.Code, rec.Body)
	}
	requireLockRefusal(t, mfaLoginFrom(t, f, "203.0.113.2", fixtureCode(t, secret)), locked)
}

func TestCurrentPasswordGuessesAreLimitedPerAccount(t *testing.T) {
	f := newAccountFixture(t)
	enrollFixtureTOTP(t, f)
	token, _ := f.session(t, f.adminID)
	fresh := testSensitiveValue("fresh")
	limit := users.LimitFor(users.FactorCurrentPassword)
	change := func(addr, current string) *httptest.ResponseRecorder {
		return f.doFrom(t, addr, http.MethodPost, "/api/v1/auth/me/password", token, map[string]string{"currentPassword": current, "newPassword": fresh})
	}
	for i := 0; i < limit.MaxFailures; i++ {
		if rec := change(fmt.Sprintf("192.0.2.%d", i+1), "wrong"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("wrong current password %d = %d %s", i, rec.Code, rec.Body)
		}
	}
	const locked = "too many failed current password attempts"
	requireLockRefusal(t, change("198.51.100.1", testPassword), locked)
	requireLockRefusal(t, f.doFrom(t, "198.51.100.2", http.MethodPost, "/api/v1/auth/me/mfa/disable", token, map[string]string{"currentPassword": testPassword, "code": "000000"}), locked)
	if n := countDenied(t, f, "current password locked after repeated failures"); n != 1 {
		t.Fatalf("lock records = %d, want 1", n)
	}
	requireAuditDetail(t, f, "auth.password.change", "current password locked after repeated failures")
	if u, err := f.users.GetByID(context.Background(), f.adminID); err != nil || !u.MFAEnabled {
		t.Fatalf("locked checks changed MFA: %+v, %v", u, err)
	}
	if status, body := f.do(t, http.MethodPost, "/api/v1/auth/login", "", map[string]string{"username": "acct-admin", "password": testPassword}); status != http.StatusOK {
		t.Fatalf("password login while the current-password check is locked = %d %s", status, body)
	}
}

func TestMFALabModeKeepsCodeGuessesUnlimited(t *testing.T) {
	f := newAccountFixture(t)
	t.Setenv("CONTAIND_LAB_MODE", "1")
	f.server = NewServerWithEngineAndServices(&mockStore{}, f.audits, nil, nil, f.users)
	secret := enrollFixtureTOTP(t, f)
	for i := 0; i <= users.LimitFor(users.FactorTOTP).MaxFailures; i++ {
		if rec := mfaLoginFrom(t, f, fmt.Sprintf("192.0.2.%d", i+1), "000000"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("lab wrong code %d = %d %s", i, rec.Code, rec.Body)
		}
	}
	if rec := mfaLoginFrom(t, f, "198.51.100.1", fixtureCode(t, secret)); rec.Code != http.StatusOK {
		t.Fatalf("lab right code = %d %s", rec.Code, rec.Body)
	}
}
