// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
	"github.com/tonylturner/containd/pkg/common/evidence"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/users"
)

func TestAuditAccountAndMFAFailuresDoNotUndoMutations(t *testing.T) {
	f := newAccountFixture(t)
	observed, backend := newEvidenceStore(t)
	backend.err = errors.New("unwritable audit")
	f.server = NewServerWithEngineAndServices(&mockStore{}, observed, nil, nil, f.users)
	token, _ := f.session(t, f.adminID)
	check := func(action string) {
		t.Helper()
		if len(backend.attempts) == 0 || backend.attempts[len(backend.attempts)-1].Action != action {
			t.Fatalf("missing attempted %s: %+v", action, backend.attempts)
		}
		s := observed.AuditStatus()
		if s.State != evidence.StateDegraded || s.Failures != uint64(len(backend.attempts)) {
			t.Fatalf("%+v", s)
		}
	}
	var target users.User
	if err := json.Unmarshal(f.mustDo(t, http.MethodPost, "/api/v1/users", token, map[string]string{"username": "audit-target", "role": "view", "password": testPassword}), &target); err != nil {
		t.Fatal(err)
	}
	check("auth.user.create")
	if _, err := f.users.GetByID(context.Background(), target.ID); err != nil {
		t.Fatal("create rolled back", err)
	}
	base := "/api/v1/users/" + target.ID
	f.mustDo(t, http.MethodPatch, base, token, map[string]string{"role": "admin"})
	check("auth.user.update")
	if u, err := f.users.GetByID(context.Background(), target.ID); err != nil || u.Role != "admin" {
		t.Fatalf("role: %+v %v", u, err)
	}
	fresh := testSensitiveValue("audit-admin-set")
	f.mustDo(t, http.MethodPost, base+"/password", token, map[string]string{"password": fresh})
	check("auth.password.set_admin")
	if err := f.users.CheckCurrentPassword(context.Background(), target.ID, fresh, time.Now()); err != nil {
		t.Fatal("password rolled back", err)
	}
	for _, step := range []struct {
		path, action string
		required     bool
	}{
		{"require", "auth.mfa.require_admin", true}, {"grace", "auth.mfa.extend_grace_admin", true}, {"clear", "auth.mfa.clear_admin", false},
	} {
		f.mustDo(t, http.MethodPost, base+"/mfa/"+step.path, token, map[string]string{})
		check(step.action)
		if u, err := f.users.GetByID(context.Background(), target.ID); err != nil || u.MFARequired != step.required {
			t.Fatalf("MFA requirement: %+v %v", u, err)
		}
	}
	var enrollment mfaEnrollResponse
	if err := json.Unmarshal(f.mustDo(t, http.MethodPost, "/api/v1/auth/me/mfa/enroll", token, map[string]string{}), &enrollment); err != nil {
		t.Fatal(err)
	}
	code, err := totp.GenerateCode(enrollment.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	f.mustDo(t, http.MethodPost, "/api/v1/auth/me/mfa/enable", token, map[string]string{"challengeToken": enrollment.ChallengeToken, "code": code})
	check("auth.mfa.enable")
	if u, err := f.users.GetByID(context.Background(), f.adminID); err != nil || !u.MFAEnabled {
		t.Fatalf("MFA enable: %+v %v", u, err)
	}
	if err := f.users.SetTOTP(context.Background(), target.ID, enrollment.Secret); err != nil {
		t.Fatal(err)
	}
	f.mustDo(t, http.MethodPost, base+"/mfa/disable", token, map[string]string{})
	check("auth.mfa.disable_admin")
	if u, err := f.users.GetByID(context.Background(), target.ID); err != nil || u.MFAEnabled {
		t.Fatalf("MFA disable: %+v %v", u, err)
	}
	// The current session survives its own credential change, including audit failure.
	own := testSensitiveValue("audit-own")
	f.mustDo(t, http.MethodPost, "/api/v1/auth/me/password", token, map[string]string{"currentPassword": testPassword, "newPassword": own})
	check("auth.password.change")
	if err := f.users.CheckCurrentPassword(context.Background(), f.adminID, own, time.Now()); err != nil {
		t.Fatal(err)
	}
	f.mustDo(t, http.MethodDelete, base, token, nil)
	check("auth.user.delete")
	if _, err := f.users.GetByID(context.Background(), target.ID); !errors.Is(err, users.ErrNotFound) {
		t.Fatalf("delete rolled back: %v", err)
	}
}

type cancelAfterUpdate struct {
	users.Store
	cancel context.CancelFunc
}

func (s cancelAfterUpdate) Update(ctx context.Context, id string, patch users.Patch) (*users.User, error) {
	u, err := s.Store.Update(ctx, id, patch)
	if err == nil {
		s.cancel()
	}
	return u, err
}

func TestAuditCompletedMutationSurvivesCanceledRequest(t *testing.T) {
	f := newAccountFixture(t)
	observed, backend := newEvidenceStore(t)
	token, _ := f.session(t, f.adminID)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	userStore := cancelAfterUpdate{Store: f.users, cancel: cancel}
	server := NewServerWithEngineAndServices(&mockStore{}, observed, nil, nil, userStore)
	req := jwtAuthedRequest(http.MethodPatch, "/api/v1/auth/me", bytes.NewBufferString(`{"firstName":"Completed"}`), token).WithContext(ctx)
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	if rec.Code != 200 || ctx.Err() == nil {
		t.Fatalf("status=%d canceled=%v body=%s", rec.Code, ctx.Err(), rec.Body)
	}
	if observed.Successes() != 1 || len(backend.attempts) != 1 {
		t.Fatalf("completed operation unaudited: %+v", observed.AuditStatus())
	}
	if u, err := f.users.GetByID(context.Background(), f.adminID); err != nil || u.FirstName != "Completed" {
		t.Fatalf("%+v %v", u, err)
	}
}

func TestAuditTLSFailureStillReturnsReplacementSuccess(t *testing.T) {
	dir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.System.Mgmt.TLSCertFile = filepath.Join(dir, "cert.pem")
	cfg.System.Mgmt.TLSKeyFile = filepath.Join(dir, "key.pem")
	t.Setenv("CONTAIND_TLS_CERT_FILE", "")
	t.Setenv("CONTAIND_TLS_KEY_FILE", "")
	observed, backend := newEvidenceStore(t)
	backend.err = errors.New("audit unavailable")
	router := gin.New()
	router.Use(withAuditStore(observed))
	router.POST("/upload", tlsCertUploadHandler(&mockStore{cfg: cfg}, dir))
	cert, key := generateTestCertPEM(t)
	body, err := json.Marshal(setTLSCertRequest{CertPEM: cert, KeyPEM: key})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader(body)))
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	for path, want := range map[string]string{cfg.System.Mgmt.TLSCertFile: cert, cfg.System.Mgmt.TLSKeyFile: key} {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(bytes.TrimSpace(got), bytes.TrimSpace([]byte(want))) {
			t.Fatalf("replacement missing: %s %v", path, err)
		}
	}
	if observed.AuditStatus().Failures != 1 || backend.attempts[0].Action != "system.tls.cert.set" {
		t.Fatalf("unobserved: %+v", observed.AuditStatus())
	}
}

func TestAuditMFAOwnDisableFailureStillCompletes(t *testing.T) {
	f := newAccountFixture(t)
	observed, backend := newEvidenceStore(t)
	backend.err = errors.New("unwritable audit")
	enrollment, err := users.GenerateTOTPEnrollment("containd", "acct-admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.users.SetTOTP(context.Background(), f.adminID, enrollment.Secret); err != nil {
		t.Fatal(err)
	}
	f.server = NewServerWithEngineAndServices(&mockStore{}, observed, nil, nil, f.users)
	token, _ := f.session(t, f.adminID)
	code, err := totp.GenerateCode(enrollment.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	f.mustDo(t, http.MethodPost, "/api/v1/auth/me/mfa/disable", token, map[string]string{"currentPassword": testPassword, "code": code})
	if u, err := f.users.GetByID(context.Background(), f.adminID); err != nil || u.MFAEnabled {
		t.Fatalf("disable rolled back: %+v %v", u, err)
	}
	if observed.AuditStatus().Failures != 1 || len(backend.attempts) != 1 || backend.attempts[0].Action != "auth.mfa.disable" {
		t.Fatalf("audit: %+v", observed.AuditStatus())
	}
}
