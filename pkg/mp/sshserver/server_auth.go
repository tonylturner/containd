// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package sshserver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"

	"github.com/tonylturner/containd/pkg/cp/users"
)

func (s *Server) passwordCallback() func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		allow, _, err := s.authPolicy(context.Background())
		if err != nil || !allow {
			return nil, errors.New("password auth disabled")
		}
		key := limiterKey(conn.RemoteAddr(), conn.User())
		if ok, _ := s.pwLimiter.Allow(key); !ok {
			return nil, errTooManyAttempts
		}
		u, err := s.opts.UserStore.GetByUsername(context.Background(), conn.User())
		if err != nil || u == nil {
			return nil, s.refuseLogin(conn, "unknown user", errInvalidCredentials)
		}
		if strings.ToLower(strings.TrimSpace(u.Role)) != "admin" {
			return nil, s.refuseLogin(conn, "not an admin", errAdminRequired)
		}
		if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), password) != nil {
			return nil, s.refuseLogin(conn, "invalid password", errInvalidCredentials)
		}
		// A pending second step keeps the failure count until it succeeds.
		perms, err := s.assureAccount(conn, u, factorPassword)
		if err == nil {
			s.pwLimiter.Success(key)
		}
		return perms, err
	}
}

// limiterKey counts attempts per client host and user. The source port is
// excluded: every connection has a new one.
func limiterKey(remote net.Addr, user string) string {
	host := remote.String()
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return host + "|" + strings.ToLower(user)
}

// publicKeyCallback checks one offered key and collects refusals for the
// connection. Outside lab mode, key logins share the password login limit.
func (s *Server) publicKeyCallback(refusals *keyRefusals) func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if !s.opts.LabMode {
			if ok, _ := s.pwLimiter.Allow(limiterKey(conn.RemoteAddr(), conn.User())); !ok {
				return nil, errTooManyAttempts
			}
		}
		u, err := s.opts.UserStore.GetByUsername(context.Background(), conn.User())
		if err != nil || u == nil {
			refusals.add(conn, "unknown user", key)
			return nil, errors.New("invalid user")
		}
		if strings.ToLower(strings.TrimSpace(u.Role)) != "admin" {
			refusals.add(conn, "not an admin", key)
			return nil, errAdminRequired
		}
		_, dir, err := s.authPolicy(context.Background())
		if err != nil {
			return nil, err
		}
		ok, err := isAuthorizedKey(dir, conn.User(), key)
		if err != nil {
			return nil, err
		}
		if !ok {
			refusals.add(conn, "public key not authorized", key)
			return nil, errors.New("unauthorized key")
		}
		return userPermissions(u), nil
	}
}

// verifiedPublicKeyCallback applies account assurance once the client has
// proven possession of an authorized key. The key is the possession factor,
// so it does not ask for a TOTP code.
func (s *Server) verifiedPublicKeyCallback() func(conn ssh.ConnMetadata, key ssh.PublicKey, perms *ssh.Permissions, algorithm string) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, _ ssh.PublicKey, perms *ssh.Permissions, _ string) (*ssh.Permissions, error) {
		if s.opts.LabMode {
			return perms, nil
		}
		u, err := s.opts.UserStore.GetByID(context.Background(), perms.Extensions["user_id"])
		if err != nil || u == nil {
			return nil, errors.New("invalid user")
		}
		perms, err = s.assureAccount(conn, u, factorPublicKey)
		if err == nil {
			s.pwLimiter.Success(limiterKey(conn.RemoteAddr(), conn.User()))
		}
		return perms, err
	}
}

func (s *Server) authPolicy(ctx context.Context) (bool, string, error) {
	if s.opts.AuthPolicy != nil {
		return s.opts.AuthPolicy(ctx)
	}
	return s.opts.AllowPassword, s.opts.AuthorizedKeysDir, nil
}

func isAuthorizedKey(dir, username string, presented ssh.PublicKey) (bool, error) {
	return hasAuthorizedKey(dir, username, func(pub ssh.PublicKey) bool {
		return bytes.Equal(pub.Marshal(), presented.Marshal())
	}), nil
}

// ValidateAdminAuthorizedKey checks the same files and key parser used at login,
// and only accepts keys belonging to an existing admin.
func ValidateAdminAuthorizedKey(ctx context.Context, store users.Store, dir string) error {
	if store == nil {
		return errors.New("ssh.allowPassword=false requires a usable admin authorized key; user store unavailable")
	}
	admins, err := store.List(ctx)
	if err != nil {
		return fmt.Errorf("cannot verify SSH admin authorized keys: %w", err)
	}
	for _, u := range admins {
		if strings.EqualFold(strings.TrimSpace(u.Role), "admin") && hasAuthorizedKey(dir, u.Username, func(ssh.PublicKey) bool { return true }) {
			return nil
		}
	}
	return errors.New("ssh.allowPassword=false would lock out SSH access: enroll a usable authorized key for an admin first")
}

func hasAuthorizedKey(dir, username string, match func(ssh.PublicKey) bool) bool {
	if !validKeyUsername(username) {
		return false
	}
	candidates := []string{
		filepath.Join(dir, username),
		filepath.Join(dir, username+".pub"),
		filepath.Join(dir, username, "authorized_keys"),
	}
	for _, p := range candidates {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for len(b) > 0 {
			pub, _, _, rest, err := ssh.ParseAuthorizedKey(b)
			if err != nil {
				break
			}
			if match(pub) {
				return true
			}
			b = rest
		}
	}
	return false
}

func validKeyUsername(username string) bool {
	return username != "" && username != "." && username != ".." && filepath.Base(username) == username
}

func (s *Server) issueToken(ctx context.Context, username, userID string) (token string, sessionID string, err error) {
	if s.opts.LabMode && len(s.opts.JWTSecret) == 0 {
		return "lab", "", nil
	}
	u, err := s.opts.UserStore.GetByUsername(ctx, username)
	if err != nil || u == nil {
		return "", "", errors.New("user not found")
	}
	if userID != "" && u.ID != userID {
		return "", "", errors.New("user mismatch")
	}
	sess, err := s.opts.UserStore.CreateSession(ctx, u.ID, 5*time.Minute, 4*time.Hour)
	if err != nil {
		return "", "", err
	}
	tok, err := signJWT(s.opts.JWTSecret, u.ID, u.Username, u.Role, sess.ID, sess.ExpiresAt)
	if err != nil {
		_ = s.opts.UserStore.RevokeSession(ctx, sess.ID)
		return "", "", err
	}
	return tok, sess.ID, nil
}

func signJWT(secret []byte, userID string, username any, role any, jti string, exp time.Time) (string, error) {
	claims := jwt.MapClaims{
		"sub":      userID,
		"username": username,
		"role":     role,
		"jti":      jti,
		"iat":      time.Now().UTC().Unix(),
		"exp":      exp.Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tok.SignedString(secret)
}

// authorizedKeyFingerprint returns the SHA256 fingerprint of a validated
// authorized-key line, for audit records.
func authorizedKeyFingerprint(line string) string {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(line)))
	if err != nil {
		return ""
	}
	return ssh.FingerprintSHA256(pub)
}

func (s *Server) EnsureAuthorizedKeysDir() {
	_ = os.MkdirAll(s.opts.AuthorizedKeysDir, 0o700)
}

func (s *Server) SeedAuthorizedKey(username string, authorizedKeyLine string) error {
	username = strings.TrimSpace(username)
	if !validKeyUsername(username) {
		return errors.New("SSH key username must be a single non-empty filename")
	}
	line := strings.TrimSpace(authorizedKeyLine)
	if line == "" {
		return errors.New("authorized key required")
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line)); err != nil {
		return fmt.Errorf("invalid authorized key: %w", err)
	}

	_, dir, err := s.authPolicy(context.Background())
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	dst := filepath.Join(dir, username+".pub")
	if b, err := os.ReadFile(dst); err == nil {
		if bytes.Contains(b, []byte(line)) {
			return nil
		}
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		return err
	}
	return nil
}
