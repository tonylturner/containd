// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package sshserver

import (
	"context"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"

	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/users"
)

// Outside lab mode, SSH applies the same account assurance as web login after
// the first factor: an expired MFA enrollment grace refuses login, a password
// login of an MFA account needs a TOTP code, and an account marked for a
// password change must change it. The second steps use keyboard-interactive
// authentication, so the CLI, menu and shell open only after they succeed.

const (
	passwordRules           = "Use at least 8 characters with an uppercase letter, a lowercase letter and a digit."
	maxPasswordChangeRounds = 3
	mfaEnrollmentBanner     = "MFA is required for this account and its enrollment grace period has ended.\r\n" +
		"Sign in to the containd web UI to enroll an authenticator app, then retry SSH.\r\n"
)

var (
	errMFASetupRequired   = errors.New("mfa setup required")
	errInvalidCredentials = errors.New("invalid credentials")
	errTooManyAttempts    = errors.New("too many login attempts; retry later")
)

type firstFactor int

const (
	factorPassword firstFactor = iota
	factorPublicKey
)

func userPermissions(u *users.StoredUser) *ssh.Permissions {
	return &ssh.Permissions{Extensions: map[string]string{"user_id": u.ID}}
}

func mfaEnrolled(u *users.StoredUser) bool {
	return u.MFAEnabled && strings.TrimSpace(u.TOTPSecret) != ""
}

// assureAccount returns the final permissions, a partial success that
// continues with keyboard-interactive steps, or a refusal.
func (s *Server) assureAccount(conn ssh.ConnMetadata, u *users.StoredUser, factor firstFactor) (*ssh.Permissions, error) {
	if s.opts.LabMode {
		return userPermissions(u), nil
	}
	if err := s.refuseExpiredMFAGrace(conn, u); err != nil {
		return nil, err
	}
	step := &assuranceStep{
		server:         s,
		userID:         u.ID,
		key:            limiterKey(conn),
		requireTOTP:    factor == factorPassword,
		confirmCurrent: factor == factorPublicKey,
	}
	if !step.pending(u) {
		return userPermissions(u), nil
	}
	return nil, &ssh.PartialSuccessError{Next: ssh.ServerAuthCallbacks{
		KeyboardInteractiveCallback: step.challenge,
	}}
}

func (s *Server) refuseExpiredMFAGrace(conn ssh.ConnMetadata, u *users.StoredUser) error {
	if !users.IsMFAGraceExpired(u, time.Now()) {
		return nil
	}
	s.auditLogin(conn, "denied", "mfa setup required")
	return &ssh.BannerError{Err: errMFASetupRequired, Message: mfaEnrollmentBanner}
}

// assuranceStep holds one connection's keyboard-interactive progress, so a
// retried challenge does not ask again for a TOTP code that already passed.
type assuranceStep struct {
	server          *Server
	userID          string
	key             string
	requireTOTP     bool
	confirmCurrent  bool
	totpDone        bool
	currentVerified bool
}

func (a *assuranceStep) pending(u *users.StoredUser) bool {
	return a.needsTOTP(u) || u.MustChangePassword
}

func (a *assuranceStep) needsTOTP(u *users.StoredUser) bool {
	return a.requireTOTP && !a.totpDone && mfaEnrolled(u)
}

func (a *assuranceStep) challenge(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	s := a.server
	if ok, _ := s.pwLimiter.Allow(a.key); !ok {
		return nil, errTooManyAttempts
	}
	// Re-read the account: an admin may have changed it since the first factor.
	u, err := s.opts.UserStore.GetByID(context.Background(), a.userID)
	if err != nil || u == nil {
		return nil, errInvalidCredentials
	}
	if err := s.refuseExpiredMFAGrace(conn, u); err != nil {
		return nil, err
	}
	if a.needsTOTP(u) {
		if err := a.verifyTOTP(conn, u, client); err != nil {
			return nil, err
		}
	}
	if u.MustChangePassword {
		if err := a.changePassword(conn, u, client); err != nil {
			return nil, err
		}
	}
	s.pwLimiter.Success(a.key)
	return userPermissions(u), nil
}

func (a *assuranceStep) verifyTOTP(conn ssh.ConnMetadata, u *users.StoredUser, client ssh.KeyboardInteractiveChallenge) error {
	answers, err := client("", "Two-factor authentication is enabled for this account.", []string{"Authentication code: "}, []bool{false})
	if err != nil {
		return err
	}
	if len(answers) != 1 || !users.ValidateTOTP(u.TOTPSecret, answers[0], time.Now()) {
		a.server.pwLimiter.Fail(a.key)
		a.server.auditLogin(conn, "denied", "invalid totp code")
		return errors.New("invalid authentication code")
	}
	a.totpDone = true
	return nil
}

// changePassword applies the forced change with the store's password rules.
// A key login confirms the current password first, as the web change does.
func (a *assuranceStep) changePassword(conn ssh.ConnMetadata, u *users.StoredUser, client ssh.KeyboardInteractiveChallenge) error {
	if err := users.CheckPasswordChange(); err != nil {
		return err
	}
	instruction := "You must change your password before continuing. " + passwordRules
	for round := 0; round < maxPasswordChangeRounds; round++ {
		questions := []string{"New password: ", "Retype new password: "}
		confirm := a.confirmCurrent && !a.currentVerified
		if confirm {
			questions = append([]string{"Current password: "}, questions...)
		}
		answers, err := client("Password change required", instruction, questions, make([]bool, len(questions)))
		if err != nil {
			return err
		}
		if len(answers) != len(questions) {
			return errors.New("incomplete password change response")
		}
		if confirm {
			if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(answers[0])) != nil {
				a.server.pwLimiter.Fail(a.key)
				return errInvalidCredentials
			}
			a.currentVerified = true
			answers = answers[1:]
		}
		if answers[0] != answers[1] {
			instruction = "The passwords do not match. " + passwordRules
			continue
		}
		err = a.server.opts.UserStore.SetPassword(context.Background(), u.ID, answers[0])
		if users.IsPasswordPolicyError(err) {
			instruction = "Password not accepted: " + err.Error() + ". " + passwordRules
			continue
		}
		if err != nil {
			return err
		}
		a.server.audit(conn.User(), audit.Record{
			Action: "auth.password.change",
			Target: u.Username,
			Detail: "forced change at ssh login",
		})
		return nil
	}
	return errors.New("password change not completed")
}

func (s *Server) auditLogin(conn ssh.ConnMetadata, result, detail string) {
	s.audit(conn.User(), audit.Record{
		Action: "ssh.login",
		Target: conn.RemoteAddr().String(),
		Result: result,
		Detail: detail,
	})
}

// audit records an SSH-originated event for actor.
func (s *Server) audit(actor string, rec audit.Record) {
	if s.opts.AuditStore == nil {
		return
	}
	rec.Actor = actor
	rec.Source = "ssh"
	if rec.Result == "" {
		rec.Result = "success"
	}
	_ = s.opts.AuditStore.Add(context.Background(), rec)
}
