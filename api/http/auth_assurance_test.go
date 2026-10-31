// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"
	"github.com/tonylturner/containd/pkg/cp/users"
)

func fixtureChallenge(t *testing.T, f accountFixture) string {
	t.Helper()
	var challenge mfaLoginChallengeResponse
	body := f.mustDo(t, http.MethodPost, "/api/v1/auth/login", "", map[string]string{"username": "acct-admin", "password": testPassword})
	if err := json.Unmarshal(body, &challenge); err != nil || challenge.MFAChallengeToken == "" {
		t.Fatalf("challenge = %s %v", body, err)
	}
	return challenge.MFAChallengeToken
}

func TestMFAChallengeReplayWithLaterCode(t *testing.T) {
	f := newAccountFixture(t)
	secret := enrollFixtureTOTP(t, f)
	challenge := fixtureChallenge(t, f)
	f.mustDo(t, http.MethodPost, "/api/v1/auth/login/mfa", "", map[string]string{"challengeToken": challenge, "code": fixtureCode(t, secret)})
	later, err := totp.GenerateCode(secret, time.Now().Add(time.Duration(users.TOTPPeriod)*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if status, body := f.do(t, http.MethodPost, "/api/v1/auth/login/mfa", "", map[string]string{"challengeToken": challenge, "code": later}); status != http.StatusUnauthorized {
		t.Fatalf("replay = %d %s", status, body)
	}
	// The next step really is valid now: the fresh challenge accepts it.
	fresh := fixtureChallenge(t, f)
	f.mustDo(t, http.MethodPost, "/api/v1/auth/login/mfa", "", map[string]string{"challengeToken": fresh, "code": later})
}

func TestMFAChallengeRefusedAfterPasswordChange(t *testing.T) {
	f := newAccountFixture(t)
	secret := enrollFixtureTOTP(t, f)
	challenge := fixtureChallenge(t, f)
	if err := f.users.SetPassword(context.Background(), f.adminID, testSensitiveValue("new-password")); err != nil {
		t.Fatal(err)
	}
	if status, body := f.do(t, http.MethodPost, "/api/v1/auth/login/mfa", "", map[string]string{"challengeToken": challenge, "code": fixtureCode(t, secret)}); status != http.StatusUnauthorized {
		t.Fatalf("old challenge = %d %s", status, body)
	}
}

func TestLastAdminHTTPConflict(t *testing.T) {
	f := newAccountFixture(t)
	token, _ := f.session(t, f.adminID)
	for _, method := range []string{http.MethodPatch, http.MethodDelete} {
		if status, body := f.do(t, method, "/api/v1/users/"+f.adminID, token, map[string]string{"role": "view"}); status != http.StatusConflict {
			t.Fatalf("%s = %d %s", method, status, body)
		}
	}
}

func TestEnrollmentChallengeInvalidated(t *testing.T) {
	f := newAccountFixture(t)
	token, _ := f.session(t, f.adminID)
	var enroll mfaEnrollResponse
	if err := json.Unmarshal(f.mustDo(t, http.MethodPost, "/api/v1/auth/me/mfa/enroll", token, map[string]string{}), &enroll); err != nil {
		t.Fatal(err)
	}
	f.mustDo(t, http.MethodPost, "/api/v1/auth/me/password", token, map[string]string{"currentPassword": testPassword, "newPassword": testSensitiveValue("changed-password")})
	// The acting session remains valid; only its pending enrollment is invalidated.
	if status, body := f.do(t, http.MethodPost, "/api/v1/auth/me/mfa/enable", token, map[string]string{"challengeToken": enroll.ChallengeToken, "code": fixtureCode(t, enroll.Secret)}); status != http.StatusUnauthorized {
		t.Fatalf("stale enrollment = %d %s", status, body)
	}
}

func TestLabSessionlessRangerDangerJWT(t *testing.T) {
	f := newAccountFixture(t)
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "rangerdanger-backend", "role": "admin", "exp": time.Now().Add(time.Hour).Unix()}).SignedString([]byte(testJWTSecret))
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := f.do(t, http.MethodGet, "/api/v1/users", token, nil); status != http.StatusUnauthorized {
		t.Fatalf("normal mode sessionless token = %d", status)
	}
	t.Setenv("CONTAIND_LAB_MODE", "1")
	f.server = NewServerWithEngineAndServices(&mockStore{}, f.audits, nil, nil, f.users)
	f.mustDo(t, http.MethodGet, "/api/v1/users", token, nil)
}
