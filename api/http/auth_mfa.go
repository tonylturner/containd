// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/users"
)

const (
	mfaChallengePurposeLogin  = "mfa_login"
	mfaChallengePurposeEnroll = "mfa_enroll"
	mfaChallengeTTL           = 5 * time.Minute
)

type mfaChallengeClaims struct {
	Purpose string `json:"purpose"`
	Secret  string `json:"secret,omitempty"`
	jwt.RegisteredClaims
}

type mfaLoginChallengeResponse struct {
	MFARequired       bool       `json:"mfaRequired"`
	MFAMethod         string     `json:"mfaMethod"`
	MFAChallengeToken string     `json:"mfaChallengeToken"`
	User              users.User `json:"user"`
}

type mfaVerifyLoginRequest struct {
	ChallengeToken string `json:"challengeToken"`
	Code           string `json:"code"`
}

type mfaEnrollResponse struct {
	Secret         string `json:"secret"`
	OtpAuthURL     string `json:"otpauthURL"`
	QRDataURL      string `json:"qrDataURL"`
	ChallengeToken string `json:"challengeToken"`
}

type mfaEnableRequest struct {
	ChallengeToken string `json:"challengeToken"`
	Code           string `json:"code"`
}

type mfaDisableRequest struct {
	CurrentPassword string `json:"currentPassword"`
	Code            string `json:"code"`
}

func issueLoginResponse(c *gin.Context, userStore users.Store, u *users.StoredUser) {
	sess, err := userStore.CreateSession(c.Request.Context(), u.ID, idleTTL, maxTTL)
	if err != nil {
		internalError(c, err)
		return
	}
	secret := jwtSecret()
	token, err := signJWT(secret, u.ID, u.Username, u.Role, sess.ID, sess.ExpiresAt)
	if err != nil {
		apiError(c, http.StatusInternalServerError, "failed to sign token")
		return
	}
	setAuthCookie(c, token, sess.ExpiresAt)
	auditLog(c, audit.Record{
		Actor:  u.Username,
		Action: "auth.login",
		Target: u.Username,
		Detail: loginAuditDetail(u.MFAEnabled),
	})
	c.JSON(http.StatusOK, loginResponse{
		Token:     token,
		ExpiresAt: sess.ExpiresAt.Format(time.RFC3339Nano),
		User:      u.User,
	})
}

func loginAuditDetail(mfa bool) string {
	if mfa {
		return "local password + totp"
	}
	return "local password"
}

func signMFAChallenge(secret []byte, purpose string, userID string, secretValue string) (string, error) {
	claims := mfaChallengeClaims{
		Purpose: purpose,
		Secret:  secretValue,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(mfaChallengeTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tok.SignedString(secret)
}

func parseMFAChallenge(raw string, purpose string) (*mfaChallengeClaims, error) {
	claims := &mfaChallengeClaims{}
	parsed, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != "HS256" {
			return nil, jwt.ErrSignatureInvalid
		}
		return jwtSecret(), nil
	}, jwt.WithLeeway(15*time.Second))
	if err != nil || !parsed.Valid {
		return nil, errors.New("invalid or expired challenge token")
	}
	if claims.Subject == "" || claims.Purpose != purpose {
		return nil, errors.New("invalid or expired challenge token")
	}
	return claims, nil
}

func loginMFAHandler(userStore users.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		if userStore == nil || len(jwtSecret()) == 0 {
			apiError(c, http.StatusServiceUnavailable, "JWT auth not configured")
			return
		}
		var req mfaVerifyLoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			apiError(c, http.StatusBadRequest, "invalid JSON")
			return
		}
		claims, err := parseMFAChallenge(strings.TrimSpace(req.ChallengeToken), mfaChallengePurposeLogin)
		if err != nil {
			apiError(c, http.StatusUnauthorized, err.Error())
			return
		}
		u, err := userStore.GetByID(c.Request.Context(), claims.Subject)
		if err != nil {
			apiError(c, http.StatusUnauthorized, "user not found")
			return
		}
		if !u.MFAEnabled || strings.TrimSpace(u.TOTPSecret) == "" {
			apiError(c, http.StatusBadRequest, "MFA is not enabled for this account")
			return
		}
		if !users.ValidateTOTP(u.TOTPSecret, req.Code, time.Now()) {
			auditLog(c, audit.Record{
				Actor:  u.Username,
				Action: "auth.login",
				Target: u.Username,
				Result: "denied",
				Detail: "invalid totp code",
			})
			apiError(c, http.StatusUnauthorized, "invalid authentication code")
			return
		}
		issueLoginResponse(c, userStore, u)
	}
}

func enrollMyMFAHandler(userStore users.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		if userStore == nil {
			apiError(c, http.StatusServiceUnavailable, "user store unavailable")
			return
		}
		u, err := userStore.GetByID(c.Request.Context(), c.GetString(ctxUserKey))
		if err != nil {
			apiError(c, http.StatusNotFound, "user not found")
			return
		}
		if u.MFAEnabled {
			apiError(c, http.StatusConflict, "MFA is already enabled for this account")
			return
		}
		enrollment, err := users.GenerateTOTPEnrollment(users.DefaultTOTPIssuer, u.Username)
		if err != nil {
			internalError(c, err)
			return
		}
		challengeToken, err := signMFAChallenge(jwtSecret(), mfaChallengePurposeEnroll, u.ID, enrollment.Secret)
		if err != nil {
			apiError(c, http.StatusInternalServerError, "failed to create MFA enrollment")
			return
		}
		c.JSON(http.StatusOK, mfaEnrollResponse{
			Secret:         enrollment.Secret,
			OtpAuthURL:     enrollment.URL,
			QRDataURL:      enrollment.QRDataURL,
			ChallengeToken: challengeToken,
		})
	}
}

func enableMyMFAHandler(userStore users.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		if userStore == nil {
			apiError(c, http.StatusServiceUnavailable, "user store unavailable")
			return
		}
		var req mfaEnableRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			apiError(c, http.StatusBadRequest, "invalid JSON")
			return
		}
		claims, err := parseMFAChallenge(strings.TrimSpace(req.ChallengeToken), mfaChallengePurposeEnroll)
		if err != nil {
			apiError(c, http.StatusUnauthorized, err.Error())
			return
		}
		if claims.Subject != c.GetString(ctxUserKey) {
			apiError(c, http.StatusForbidden, "MFA enrollment token does not match the current user")
			return
		}
		u, err := userStore.GetByID(c.Request.Context(), claims.Subject)
		if err != nil {
			apiError(c, http.StatusNotFound, "user not found")
			return
		}
		if u.MFAEnabled {
			apiError(c, http.StatusConflict, "MFA is already enabled for this account")
			return
		}
		if !users.ValidateTOTP(claims.Secret, req.Code, time.Now()) {
			apiError(c, http.StatusUnauthorized, "invalid authentication code")
			return
		}
		if err := userStore.SetTOTP(c.Request.Context(), u.ID, claims.Secret); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		auditLog(c, audit.Record{
			Action: "auth.mfa.enable",
			Target: u.Username,
			Detail: "totp enabled",
		})
		c.JSON(http.StatusOK, gin.H{"status": "mfa_enabled"})
	}
}

func disableMyMFAHandler(userStore users.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		if userStore == nil {
			apiError(c, http.StatusServiceUnavailable, "user store unavailable")
			return
		}
		var req mfaDisableRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			apiError(c, http.StatusBadRequest, "invalid JSON")
			return
		}
		u, err := userStore.GetByID(c.Request.Context(), c.GetString(ctxUserKey))
		if err != nil {
			apiError(c, http.StatusNotFound, "user not found")
			return
		}
		if !u.MFAEnabled || strings.TrimSpace(u.TOTPSecret) == "" {
			apiError(c, http.StatusBadRequest, "MFA is not enabled for this account")
			return
		}
		if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.CurrentPassword)) != nil {
			apiError(c, http.StatusUnauthorized, "current password invalid")
			return
		}
		if !users.ValidateTOTP(u.TOTPSecret, req.Code, time.Now()) {
			apiError(c, http.StatusUnauthorized, "invalid authentication code")
			return
		}
		if err := userStore.DisableTOTP(c.Request.Context(), u.ID); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		auditLog(c, audit.Record{
			Action: "auth.mfa.disable",
			Target: u.Username,
			Detail: "totp disabled",
		})
		c.JSON(http.StatusOK, gin.H{"status": "mfa_disabled"})
	}
}

func disableUserMFAHandler(userStore users.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		if userStore == nil {
			apiError(c, http.StatusServiceUnavailable, "user store unavailable")
			return
		}
		u, err := userStore.GetByID(c.Request.Context(), c.Param("id"))
		if err != nil {
			apiError(c, http.StatusNotFound, "user not found")
			return
		}
		if !u.MFAEnabled {
			c.JSON(http.StatusOK, gin.H{"status": "already_disabled"})
			return
		}
		if err := userStore.DisableTOTP(c.Request.Context(), u.ID); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		auditLog(c, audit.Record{
			Action: "auth.mfa.disable_admin",
			Target: u.Username,
			Detail: "admin disabled totp",
		})
		c.JSON(http.StatusOK, gin.H{"status": "mfa_disabled"})
	}
}
