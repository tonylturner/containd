// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/tonylturner/containd/pkg/cp/users"
)

// AcceptTOTP checks the code without replay tracking; replay is covered
// against the SQLite store.
func (m *mockUserStore) AcceptTOTP(_ context.Context, id, code string, now time.Time) error {
	u, ok := m.users[id]
	if !ok {
		return users.ErrNotFound
	}
	if !u.MFAEnabled || !users.ValidateTOTP(u.TOTPSecret, code, now) {
		return users.ErrInvalidTOTP
	}
	return nil
}

// enrollFixtureTOTP enables TOTP for the fixture admin and returns its secret.
func enrollFixtureTOTP(t *testing.T, f accountFixture) string {
	t.Helper()
	enrollment, err := users.GenerateTOTPEnrollment(users.DefaultTOTPIssuer, "acct-admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.users.SetTOTP(context.Background(), f.adminID, enrollment.Secret); err != nil {
		t.Fatal(err)
	}
	return enrollment.Secret
}

// mfaLogin signs in the fixture admin with its password and code and returns
// the status of the code step.
func mfaLogin(t *testing.T, f accountFixture, code string) (int, []byte) {
	t.Helper()
	var challenge mfaLoginChallengeResponse
	resp := f.mustDo(t, http.MethodPost, "/api/v1/auth/login", "", map[string]string{"username": "acct-admin", "password": testPassword})
	if err := json.Unmarshal(resp, &challenge); err != nil || challenge.MFAChallengeToken == "" {
		t.Fatalf("login challenge = %s, %v", resp, err)
	}
	return f.do(t, http.MethodPost, "/api/v1/auth/login/mfa", "", map[string]string{"challengeToken": challenge.MFAChallengeToken, "code": code})
}

func fixtureCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func TestMFALoginRefusesReusedCode(t *testing.T) {
	f := newAccountFixture(t)
	secret := enrollFixtureTOTP(t, f)
	code := fixtureCode(t, secret)

	if status, body := mfaLogin(t, f, code); status != http.StatusOK {
		t.Fatalf("first login = %d %s", status, body)
	}
	if status, body := mfaLogin(t, f, code); status != http.StatusUnauthorized {
		t.Fatalf("reused code login = %d %s", status, body)
	}
	requireAudit(t, f.audits, "auth.login", "acct-admin", "denied")
	requireAuditDetail(t, f, "auth.login", "totp code reused")

	// The code a login used cannot also turn MFA off.
	token, _ := f.session(t, f.adminID)
	if status, body := f.do(t, http.MethodPost, "/api/v1/auth/me/mfa/disable", token, map[string]string{"currentPassword": testPassword, "code": code}); status != http.StatusUnauthorized {
		t.Fatalf("disable with a used code = %d %s", status, body)
	}
	requireAuditDetail(t, f, "auth.mfa.disable", "totp code reused")
}

func TestMFASelfServiceDenialsAreAudited(t *testing.T) {
	f := newAccountFixture(t)
	token, _ := f.session(t, f.adminID)

	var enrollment mfaEnrollResponse
	if err := json.Unmarshal(f.mustDo(t, http.MethodPost, "/api/v1/auth/me/mfa/enroll", token, map[string]string{}), &enrollment); err != nil {
		t.Fatal(err)
	}
	if status, _ := f.do(t, http.MethodPost, "/api/v1/auth/me/mfa/enable", token, map[string]string{"challengeToken": enrollment.ChallengeToken, "code": "000000"}); status != http.StatusUnauthorized {
		t.Fatalf("enable with a wrong code = %d", status)
	}
	requireAuditDetail(t, f, "auth.mfa.enable", "invalid totp code")
	f.mustDo(t, http.MethodPost, "/api/v1/auth/me/mfa/enable", token, map[string]string{"challengeToken": enrollment.ChallengeToken, "code": fixtureCode(t, enrollment.Secret)})

	if status, _ := f.do(t, http.MethodPost, "/api/v1/auth/me/mfa/disable", token, map[string]string{"currentPassword": "wrong", "code": fixtureCode(t, enrollment.Secret)}); status != http.StatusUnauthorized {
		t.Fatalf("disable with a wrong password = %d", status)
	}
	requireAuditDetail(t, f, "auth.mfa.disable", "current password invalid")
	if status, _ := f.do(t, http.MethodPost, "/api/v1/auth/me/mfa/disable", token, map[string]string{"currentPassword": testPassword, "code": "000000"}); status != http.StatusUnauthorized {
		t.Fatalf("disable with a wrong code = %d", status)
	}
	requireAuditDetail(t, f, "auth.mfa.disable", "invalid totp code")
	if u, err := f.users.GetByID(context.Background(), f.adminID); err != nil || !u.MFAEnabled {
		t.Fatalf("refused disable changed MFA: %+v, %v", u, err)
	}
}

func TestMFALabModeKeepsCodeReuse(t *testing.T) {
	f := newAccountFixture(t)
	t.Setenv("CONTAIND_LAB_MODE", "1")
	f.server = NewServerWithEngineAndServices(&mockStore{}, f.audits, nil, nil, f.users)
	secret := enrollFixtureTOTP(t, f)
	code := fixtureCode(t, secret)
	for i := 0; i < 2; i++ {
		if status, body := mfaLogin(t, f, code); status != http.StatusOK {
			t.Fatalf("lab login %d = %d %s", i, status, body)
		}
	}
	// Lab auth acts as the containd account.
	labAdmin, err := f.users.Create(context.Background(), users.User{Username: "containd", Role: "admin"}, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	token, _ := f.session(t, labAdmin.ID)
	var enrollment mfaEnrollResponse
	if err := json.Unmarshal(f.mustDo(t, http.MethodPost, "/api/v1/auth/me/mfa/enroll", token, map[string]string{}), &enrollment); err != nil {
		t.Fatal(err)
	}
	if status, _ := f.do(t, http.MethodPost, "/api/v1/auth/me/mfa/enable", token, map[string]string{"challengeToken": enrollment.ChallengeToken, "code": "000000"}); status != http.StatusUnauthorized {
		t.Fatalf("lab enable with a wrong code = %d", status)
	}
	records, err := f.audits.List(context.Background(), 500)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range records {
		if r.Action == "auth.mfa.enable" && r.Result == "denied" {
			t.Fatalf("lab mode wrote a new denial record: %+v", r)
		}
	}
}

func requireAuditDetail(t *testing.T, f accountFixture, action, detail string) {
	t.Helper()
	records, err := f.audits.List(context.Background(), 500)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range records {
		if r.Action == action && r.Result == "denied" && r.Detail == detail {
			if r.Actor != "acct-admin" || r.Target != "acct-admin" {
				t.Fatalf("%s denial actor/target = %q/%q", action, r.Actor, r.Target)
			}
			return
		}
	}
	t.Fatalf("no denied %s audit with detail %q in %+v", action, detail, records)
}
