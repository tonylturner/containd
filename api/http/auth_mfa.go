// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/tonylturner/containd/pkg/common/labmode"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/users"
)

const (
	mfaChallengePurposeLogin  = users.MFAChallengeLogin
	mfaChallengePurposeEnroll = users.MFAChallengeEnroll
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

func signMFAChallenge(ctx context.Context, store users.Store, secret []byte, purpose string, u *users.StoredUser, secretValue string) (string, error) {
	expires := time.Now().UTC().Add(mfaChallengeTTL)
	id, err := store.CreateMFAChallenge(ctx, u, purpose, expires)
	if err != nil {
		return "", err
	}
	claims := mfaChallengeClaims{
		Purpose: purpose,
		Secret:  secretValue,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        id,
			Subject:   u.ID,
			ExpiresAt: jwt.NewNumericDate(expires),
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
	if claims.ID == "" || claims.Subject == "" || claims.Purpose != purpose {
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
		if err := userStore.RedeemLoginMFA(c.Request.Context(), claims.ID, u.ID, req.Code, time.Now()); err != nil {
			if errors.Is(err, users.ErrMFAChallenge) {
				apiError(c, http.StatusUnauthorized, err.Error())
				return
			}
			refuseFactor(c, err, func(detail string) {
				auditLog(c, audit.Record{
					Actor:  u.Username,
					Action: "auth.login",
					Target: u.Username,
					Result: "denied",
					Detail: detail,
				})
			})
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
		challengeToken, err := signMFAChallenge(c.Request.Context(), userStore, jwtSecret(), mfaChallengePurposeEnroll, u, enrollment.Secret)
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
	lab := labmode.Enabled()
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
		if err := userStore.RedeemEnrollMFA(c.Request.Context(), claims.ID, u.ID, claims.Secret, req.Code, time.Now()); err != nil {
			if errors.Is(err, users.ErrMFAChallenge) {
				apiError(c, http.StatusUnauthorized, err.Error())
				return
			}
			refuseFactor(c, err, func(detail string) { auditMFADenied(c, lab, "auth.mfa.enable", u.Username, detail) })
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
	lab := labmode.Enabled()
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
		if u.MFARequired {
			apiError(c, http.StatusConflict, "MFA is required for this account; ask an admin to clear the requirement before disabling it")
			return
		}
		denied := func(detail string) { auditMFADenied(c, lab, "auth.mfa.disable", u.Username, detail) }
		if err := userStore.CheckCurrentPassword(c.Request.Context(), u.ID, req.CurrentPassword, time.Now()); err != nil {
			refuseFactor(c, err, denied)
			return
		}
		if err := userStore.AcceptTOTP(c.Request.Context(), u.ID, req.Code, time.Now()); err != nil {
			refuseFactor(c, err, denied)
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

// refuseFactor answers a refused TOTP code or current password, recording
// the refusal through record when the store says to: a locked check is
// recorded once per lock and answered 429 with Retry-After. A store failure
// is an internal error.
func refuseFactor(c *gin.Context, err error, record func(detail string)) {
	detail, write, refused := users.Refusal(err)
	if !refused {
		internalError(c, err)
		return
	}
	if write {
		record(detail)
	}
	var locked *users.FactorLockedError
	if errors.As(err, &locked) {
		c.Header("Retry-After", strconv.Itoa(int(locked.RetryAfter()/time.Second)))
		apiError(c, http.StatusTooManyRequests, err.Error())
		return
	}
	apiError(c, http.StatusUnauthorized, err.Error())
}

// auditMFADenied records a refused self-service MFA change. Lab mode keeps
// its audit trail as it was and writes none.
func auditMFADenied(c *gin.Context, lab bool, action, username, detail string) {
	if lab {
		return
	}
	auditLog(c, audit.Record{Action: action, Target: username, Result: "denied", Detail: detail})
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
		if err := userStore.DisableTOTPWithGrace(c.Request.Context(), u.ID, time.Now()); err != nil {
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

func requireUserMFAHandler(userStore users.Store) gin.HandlerFunc {
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
		var graceUntil *time.Time
		status := "mfa_required"
		if !u.MFAEnabled {
			deadline := users.MFAGraceDeadline(time.Now())
			graceUntil = &deadline
			status = "mfa_required_pending_setup"
		}
		if err := userStore.SetMFARequirement(c.Request.Context(), u.ID, true, graceUntil); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		auditLog(c, audit.Record{
			Action: "auth.mfa.require_admin",
			Target: u.Username,
			Detail: status,
		})
		resp := gin.H{"status": status}
		if graceUntil != nil {
			resp["graceUntil"] = graceUntil.Format(time.RFC3339Nano)
		}
		c.JSON(http.StatusOK, resp)
	}
}

func clearUserMFARequirementHandler(userStore users.Store) gin.HandlerFunc {
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
		if err := userStore.SetMFARequirement(c.Request.Context(), u.ID, false, nil); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		auditLog(c, audit.Record{
			Action: "auth.mfa.clear_admin",
			Target: u.Username,
			Detail: "mfa requirement cleared",
		})
		c.JSON(http.StatusOK, gin.H{"status": "mfa_requirement_cleared"})
	}
}

func extendUserMFAGraceHandler(userStore users.Store) gin.HandlerFunc {
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
		if !u.MFARequired {
			apiError(c, http.StatusConflict, "MFA is not required for this account")
			return
		}
		if u.MFAEnabled {
			c.JSON(http.StatusOK, gin.H{"status": "mfa_already_enabled"})
			return
		}
		deadline := users.MFAGraceDeadline(time.Now())
		if err := userStore.SetMFARequirement(c.Request.Context(), u.ID, true, &deadline); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		auditLog(c, audit.Record{
			Action: "auth.mfa.extend_grace_admin",
			Target: u.Username,
			Detail: "mfa grace extended",
		})
		c.JSON(http.StatusOK, gin.H{
			"status":     "mfa_grace_extended",
			"graceUntil": deadline.Format(time.RFC3339Nano),
		})
	}
}
