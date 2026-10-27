// SPDX-License-Identifier: Apache-2.0
package sshserver

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// An SSH connection's management session idles out sessionIdleTTL after its
// last request, and ends sessionMaxTTL after login.
const (
	sessionIdleTTL = 5 * time.Minute
	sessionMaxTTL  = 4 * time.Hour
)

// labToken authenticates lab-mode requests when no JWT secret is set: the
// management API then accepts any nonempty token.
const labToken = "lab"

// openSession creates the management session of an SSH login. Lab mode
// without a JWT secret has none.
func (s *Server) openSession(ctx context.Context, username, userID string) (string, error) {
	if s.opts.LabMode && len(s.opts.JWTSecret) == 0 {
		return "", nil
	}
	u, err := s.opts.UserStore.GetByUsername(ctx, username)
	if err != nil || u == nil {
		return "", errors.New("user not found")
	}
	if userID != "" && u.ID != userID {
		return "", errors.New("user mismatch")
	}
	sess, err := s.opts.UserStore.CreateSession(ctx, u.ID, sessionIdleTTL, sessionMaxTTL)
	if err != nil {
		return "", err
	}
	return sess.ID, nil
}

// sessionToken signs a token for one management request of an SSH login.
// It first extends the session's idle expiry, so the session stays usable
// while the connection is open, up to sessionMaxTTL. A revoked session
// fails.
func (s *Server) sessionToken(ctx context.Context, sessionID string) (string, error) {
	if sessionID == "" {
		return labToken, nil
	}
	sess, err := s.opts.UserStore.TouchSession(ctx, sessionID, sessionIdleTTL, sessionMaxTTL)
	if err != nil {
		return "", fmt.Errorf("SSH login session ended: %w", err)
	}
	if !time.Now().Before(sess.ExpiresAt) {
		return "", fmt.Errorf("SSH login session reached its %s limit; reconnect", sessionMaxTTL)
	}
	u, err := s.opts.UserStore.GetByID(ctx, sess.UserID)
	if err != nil || u == nil {
		return "", errors.New("SSH login session user not found")
	}
	return signJWT(s.opts.JWTSecret, u.ID, u.Username, u.Role, sess.ID, sess.ExpiresAt)
}
