// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/tonylturner/containd/pkg/cp/users"
)

func TestCallerRoleMatchesEnforcement(t *testing.T) {
	for _, lab := range []bool{false, true} {
		name, wantRole, wantAdminStatus := "session", "view", http.StatusForbidden
		if lab {
			name, wantRole, wantAdminStatus = "lab", "admin", http.StatusOK
		}
		t.Run(name, func(t *testing.T) {
			f := newAccountFixture(t)
			viewer, err := f.users.Create(context.Background(), users.User{
				Username: "role-viewer", Role: "view", FirstName: "Viewer",
				LastName: "Profile", Email: "viewer@example.test",
			}, testPassword)
			if err != nil {
				t.Fatal(err)
			}
			token, _ := f.session(t, viewer.ID)
			if lab {
				t.Setenv("CONTAIND_LAB_MODE", "1")
				f.server = NewServerWithEngineAndServices(&mockStore{}, f.audits, nil, nil, f.users)
				// No session or jti: the subject selects only the profile,
				// and even an explicit view claim cannot downgrade lab access.
				token = signTestJWT([]byte(testJWTSecret), viewer.ID, viewer.Username, "view", "", time.Now().Add(time.Hour))
			}
			checkProfile := func(body []byte) {
				t.Helper()
				var profile users.User
				if err := json.Unmarshal(body, &profile); err != nil {
					t.Fatal(err)
				}
				if profile.ID != viewer.ID || profile.Username != viewer.Username || profile.Role != wantRole ||
					profile.FirstName != viewer.FirstName || profile.LastName != viewer.LastName || profile.Email != viewer.Email {
					t.Fatalf("profile = %+v, want account %s with role %s", profile, viewer.ID, wantRole)
				}
			}
			checkProfile(f.mustDo(t, http.MethodGet, "/api/v1/auth/me", token, nil))
			checkProfile(f.mustDo(t, http.MethodPatch, "/api/v1/auth/me", token, map[string]string{"firstName": viewer.FirstName}))
			for _, path := range []string{"/api/v1/auth/session", "/api/v1/dashboard"} {
				body := f.mustDo(t, http.MethodGet, path, token, nil)
				var response struct {
					Role string          `json:"role"`
					User json.RawMessage `json:"user"`
				}
				if err := json.Unmarshal(body, &response); err != nil {
					t.Fatal(err)
				}
				checkProfile(response.User)
				if path == "/api/v1/auth/session" && response.Role != wantRole {
					t.Fatalf("session role = %q, want %q", response.Role, wantRole)
				}
			}
			if status, body := f.do(t, http.MethodGet, "/api/v1/users", token, nil); status != wantAdminStatus {
				t.Fatalf("admin route = %d %s, want %d", status, body, wantAdminStatus)
			}
			checkLogin := func(body []byte) {
				t.Helper()
				var login loginResponse
				if err := json.Unmarshal(body, &login); err != nil {
					t.Fatal(err)
				}
				profile, err := json.Marshal(login.User)
				if err != nil {
					t.Fatal(err)
				}
				checkProfile(profile)
				parsed, err := jwt.Parse(login.Token, jwtKeyFunc([]byte(testJWTSecret)))
				if err != nil {
					t.Fatal(err)
				}
				if got := parsed.Claims.(jwt.MapClaims)["role"]; got != wantRole {
					t.Fatalf("JWT role = %v, want %s", got, wantRole)
				}
				checkProfile(f.mustDo(t, http.MethodGet, "/api/v1/auth/me", login.Token, nil))
			}
			checkLogin(f.mustDo(t, http.MethodPost, "/api/v1/auth/login", "", map[string]string{
				"username": viewer.Username, "password": testPassword,
			}))
			enrollment, err := users.GenerateTOTPEnrollment("containd", viewer.Username)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.users.SetTOTP(context.Background(), viewer.ID, enrollment.Secret); err != nil {
				t.Fatal(err)
			}
			body := f.mustDo(t, http.MethodPost, "/api/v1/auth/login", "", map[string]string{
				"username": viewer.Username, "password": testPassword,
			})
			var challenge mfaLoginChallengeResponse
			if err := json.Unmarshal(body, &challenge); err != nil {
				t.Fatal(err)
			}
			if !challenge.MFARequired || challenge.User.Role != wantRole {
				t.Fatalf("MFA challenge = %+v, want role %s", challenge, wantRole)
			}
			checkLogin(f.mustDo(t, http.MethodPost, "/api/v1/auth/login/mfa", "", map[string]string{
				"challengeToken": challenge.MFAChallengeToken, "code": fixtureCode(t, enrollment.Secret),
			}))
			stored, err := f.users.GetByID(context.Background(), viewer.ID)
			if err != nil || stored.Role != "view" {
				t.Fatalf("stored role changed: %+v, %v", stored, err)
			}
		})
	}
}
