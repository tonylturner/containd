// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/tonylturner/containd/pkg/cp/users"
)

func TestLoginRequiresMFA(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	hash, _ := bcrypt.GenerateFromPassword([]byte(testPassword), 4) //nolint:gosec
	enrollment, err := users.GenerateTOTPEnrollment("containd", "admin")
	if err != nil {
		t.Fatalf("GenerateTOTPEnrollment: %v", err)
	}
	us.users["u1"] = &users.StoredUser{
		User: users.User{
			ID:         "u1",
			Username:   "admin",
			Role:       "admin",
			MFAEnabled: true,
		},
		PasswordHash: string(hash),
		TOTPSecret:   enrollment.Secret,
	}
	s := setupJWTServer(&mockStore{}, us)

	rec := httptest.NewRecorder()
	body := loginBody("admin", testPassword)
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for MFA challenge, got %d body=%s", rec.Code, rec.Body.String())
	}
	var challenge mfaLoginChallengeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &challenge); err != nil {
		t.Fatalf("invalid mfa challenge response: %v", err)
	}
	if !challenge.MFARequired || challenge.MFAChallengeToken == "" {
		t.Fatalf("expected MFA challenge response, got %+v", challenge)
	}

	verifyBody, _ := json.Marshal(map[string]string{
		"challengeToken": challenge.MFAChallengeToken,
		"code":           currentTOTPCode(t, enrollment.Secret),
	})
	rec = httptest.NewRecorder()
	req, _ = http.NewRequest(http.MethodPost, "/api/v1/auth/login/mfa", bytes.NewBuffer(verifyBody))
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for MFA verify login, got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp loginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid login response JSON: %v", err)
	}
	if resp.Token == "" {
		t.Fatal("expected non-empty token after MFA verification")
	}
}

func TestLoginAllowsPendingMFADuringGrace(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	hash, _ := bcrypt.GenerateFromPassword([]byte(testPassword), 4) //nolint:gosec
	deadline := time.Now().UTC().Add(24 * time.Hour)
	us.users["u1"] = &users.StoredUser{
		User: users.User{
			ID:            "u1",
			Username:      "admin",
			Role:          "admin",
			MFARequired:   true,
			MFAGraceUntil: &deadline,
		},
		PasswordHash: string(hash),
	}
	s := setupJWTServer(&mockStore{}, us)

	rec := httptest.NewRecorder()
	body := loginBody("admin", testPassword)
	req, _ := http.NewRequest(http.MethodPost, "/api/v1/auth/login", body)
	req.Header.Set("Content-Type", "application/json")
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for grace-period login, got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp loginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid login response JSON: %v", err)
	}
	if resp.Token == "" {
		t.Fatal("expected non-empty token during MFA grace login")
	}
	if !resp.User.MFARequired || resp.User.MFAEnabled {
		t.Fatalf("expected pending MFA requirement in login response, got %+v", resp.User)
	}
}

func TestSelfMFAEnrollEnableDisable(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	secret := []byte(testJWTSecret)
	tok, uid := addTestAdmin(us, secret)
	s := setupJWTServer(&mockStore{}, us)

	rec := httptest.NewRecorder()
	req := jwtAuthedRequest(http.MethodPost, "/api/v1/auth/me/mfa/enroll", bytes.NewBufferString(`{}`), tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("enroll mfa expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var enrollment mfaEnrollResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &enrollment); err != nil {
		t.Fatalf("invalid enroll response: %v", err)
	}
	if enrollment.Secret == "" || enrollment.ChallengeToken == "" {
		t.Fatalf("expected enrollment secret and challenge token, got %+v", enrollment)
	}

	enableBody, _ := json.Marshal(map[string]string{
		"challengeToken": enrollment.ChallengeToken,
		"code":           currentTOTPCode(t, enrollment.Secret),
	})
	rec = httptest.NewRecorder()
	req = jwtAuthedRequest(http.MethodPost, "/api/v1/auth/me/mfa/enable", bytes.NewBuffer(enableBody), tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("enable mfa expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !us.users[uid].MFAEnabled {
		t.Fatal("expected MFA to be enabled")
	}

	disableBody, _ := json.Marshal(map[string]string{
		"currentPassword": testPassword,
		"code":            currentTOTPCode(t, us.users[uid].TOTPSecret),
	})
	rec = httptest.NewRecorder()
	req = jwtAuthedRequest(http.MethodPost, "/api/v1/auth/me/mfa/disable", bytes.NewBuffer(disableBody), tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("disable mfa expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if us.users[uid].MFAEnabled {
		t.Fatal("expected MFA to be disabled")
	}
}

func TestRequiredUserCannotSelfDisableMFA(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	secret := []byte(testJWTSecret)
	tok, uid := addTestAdmin(us, secret)
	us.users[uid].MFARequired = true
	enrollment, err := users.GenerateTOTPEnrollment("containd", "admin")
	if err != nil {
		t.Fatalf("GenerateTOTPEnrollment: %v", err)
	}
	us.users[uid].MFAEnabled = true
	us.users[uid].TOTPSecret = enrollment.Secret
	s := setupJWTServer(&mockStore{}, us)

	disableBody, _ := json.Marshal(map[string]string{
		"currentPassword": testPassword,
		"code":            currentTOTPCode(t, us.users[uid].TOTPSecret),
	})
	rec := httptest.NewRecorder()
	req := jwtAuthedRequest(http.MethodPost, "/api/v1/auth/me/mfa/disable", bytes.NewBuffer(disableBody), tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 when required user disables MFA, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdminCanDisableUserMFA(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	secret := []byte(testJWTSecret)
	adminTok, _ := addTestAdmin(us, secret)
	_, userID := addTestUser(us, secret, "viewer-2", "viewer2", "view", false)
	us.users[userID].MFAEnabled = true
	us.users[userID].TOTPSecret = "JBSWY3DPEHPK3PXP"
	s := setupJWTServer(&mockStore{}, us)

	rec := httptest.NewRecorder()
	req := jwtAuthedRequest(http.MethodPost, "/api/v1/users/"+userID+"/mfa/disable", bytes.NewBufferString(`{}`), adminTok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin disable mfa expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if us.users[userID].MFAEnabled {
		t.Fatal("expected target MFA to be disabled by admin")
	}
}

func TestAdminDisableRequiredUserMFASetsGrace(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	secret := []byte(testJWTSecret)
	adminTok, _ := addTestAdmin(us, secret)
	_, userID := addTestUser(us, secret, "viewer-3", "viewer3", "view", false)
	us.users[userID].MFARequired = true
	us.users[userID].MFAEnabled = true
	us.users[userID].TOTPSecret = "JBSWY3DPEHPK3PXP"
	s := setupJWTServer(&mockStore{}, us)

	rec := httptest.NewRecorder()
	req := jwtAuthedRequest(http.MethodPost, "/api/v1/users/"+userID+"/mfa/disable", bytes.NewBufferString(`{}`), adminTok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin disable mfa expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if us.users[userID].MFAEnabled {
		t.Fatal("expected target MFA to be disabled by admin")
	}
	if !us.users[userID].MFARequired || us.users[userID].MFAGraceUntil == nil {
		t.Fatalf("expected required MFA user to receive new grace window, got %+v", us.users[userID].User)
	}
}

func TestAdminCanRequireClearAndExtendUserMFA(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	secret := []byte(testJWTSecret)
	adminTok, _ := addTestAdmin(us, secret)
	_, userID := addTestUser(us, secret, "viewer-4", "viewer4", "view", false)
	s := setupJWTServer(&mockStore{}, us)

	rec := httptest.NewRecorder()
	req := jwtAuthedRequest(http.MethodPost, "/api/v1/users/"+userID+"/mfa/require", bytes.NewBufferString(`{}`), adminTok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("require mfa expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !us.users[userID].MFARequired || us.users[userID].MFAGraceUntil == nil {
		t.Fatalf("expected user MFA requirement with grace, got %+v", us.users[userID].User)
	}
	firstDeadline := us.users[userID].MFAGraceUntil.UTC()

	rec = httptest.NewRecorder()
	req = jwtAuthedRequest(http.MethodPost, "/api/v1/users/"+userID+"/mfa/grace", bytes.NewBufferString(`{}`), adminTok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("extend mfa grace expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if us.users[userID].MFAGraceUntil == nil || !us.users[userID].MFAGraceUntil.After(firstDeadline) {
		t.Fatalf("expected extended grace deadline after %v, got %+v", firstDeadline, us.users[userID].MFAGraceUntil)
	}

	rec = httptest.NewRecorder()
	req = jwtAuthedRequest(http.MethodPost, "/api/v1/users/"+userID+"/mfa/clear", bytes.NewBufferString(`{}`), adminTok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("clear mfa requirement expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if us.users[userID].MFARequired || us.users[userID].MFAGraceUntil != nil {
		t.Fatalf("expected cleared MFA requirement, got %+v", us.users[userID].User)
	}
}

func TestExpiredMFARequirementRestrictsUntilEnabled(t *testing.T) {
	t.Setenv("CONTAIND_JWT_SECRET", testJWTSecret)
	t.Setenv("CONTAIND_ADMIN_TOKEN", "")
	t.Setenv("CONTAIND_LAB_MODE", "0")
	defer t.Setenv("CONTAIND_JWT_SECRET", "")

	us := newMockUserStore()
	secret := []byte(testJWTSecret)
	tok, uid := addTestAdmin(us, secret)
	expired := time.Now().UTC().Add(-1 * time.Hour)
	us.users[uid].MFARequired = true
	us.users[uid].MFAGraceUntil = &expired
	s := setupJWTServer(&mockStore{}, us)

	rec := httptest.NewRecorder()
	req := jwtAuthedRequest(http.MethodGet, "/api/v1/config", nil, tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for expired MFA requirement on /config, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = jwtAuthedRequest(http.MethodPost, "/api/v1/auth/me/mfa/enroll", bytes.NewBufferString(`{}`), tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for /auth/me/mfa/enroll during restricted session, got %d body=%s", rec.Code, rec.Body.String())
	}
	var enrollment mfaEnrollResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &enrollment); err != nil {
		t.Fatalf("invalid enroll response: %v", err)
	}

	enableBody, _ := json.Marshal(map[string]string{
		"challengeToken": enrollment.ChallengeToken,
		"code":           currentTOTPCode(t, enrollment.Secret),
	})
	rec = httptest.NewRecorder()
	req = jwtAuthedRequest(http.MethodPost, "/api/v1/auth/me/mfa/enable", bytes.NewBuffer(enableBody), tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for /auth/me/mfa/enable during restricted session, got %d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = jwtAuthedRequest(http.MethodGet, "/api/v1/config", nil, tok)
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for /config after enabling MFA, got %d body=%s", rec.Code, rec.Body.String())
	}
}
