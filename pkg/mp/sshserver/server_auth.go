// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package sshserver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
)

func ensureHostKey(path string, rotationDays int) (ssh.Signer, error) {
	if b, err := os.ReadFile(path); err == nil {
		if rotationDays > 0 {
			info, err := os.Stat(path)
			if err == nil && time.Since(info.ModTime()) > time.Duration(rotationDays)*24*time.Hour {
				_ = os.Remove(path)
			} else {
				return ssh.ParsePrivateKey(b)
			}
		} else {
			return ssh.ParsePrivateKey(b)
		}
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	p := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, p, 0o600); err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(p)
}

func (s *Server) passwordCallback() func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		if !s.opts.AllowPassword && !s.opts.LabMode {
			return nil, errors.New("password auth disabled")
		}
		key := conn.RemoteAddr().String() + "|" + strings.ToLower(conn.User())
		if s.pwLimiter != nil {
			if ok, _ := s.pwLimiter.Allow(key); !ok {
				return nil, errors.New("too many login attempts; retry later")
			}
		}
		u, err := s.opts.UserStore.GetByUsername(context.Background(), conn.User())
		if err != nil || u == nil {
			if s.pwLimiter != nil {
				s.pwLimiter.Fail(key)
			}
			return nil, errors.New("invalid credentials")
		}
		if strings.ToLower(strings.TrimSpace(u.Role)) != "admin" {
			if s.pwLimiter != nil {
				s.pwLimiter.Fail(key)
			}
			return nil, errors.New("ssh requires admin role")
		}
		if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), password) != nil {
			if s.pwLimiter != nil {
				s.pwLimiter.Fail(key)
			}
			return nil, errors.New("invalid credentials")
		}
		if s.pwLimiter != nil {
			s.pwLimiter.Success(key)
		}
		return &ssh.Permissions{Extensions: map[string]string{"user_id": u.ID}}, nil
	}
}

func (s *Server) publicKeyCallback() func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		u, err := s.opts.UserStore.GetByUsername(context.Background(), conn.User())
		if err != nil || u == nil {
			return nil, errors.New("invalid user")
		}
		if strings.ToLower(strings.TrimSpace(u.Role)) != "admin" {
			return nil, errors.New("ssh requires admin role")
		}
		ok, err := isAuthorizedKey(s.opts.AuthorizedKeysDir, conn.User(), key)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errors.New("unauthorized key")
		}
		return &ssh.Permissions{Extensions: map[string]string{"user_id": u.ID}}, nil
	}
}

func isAuthorizedKey(dir, username string, presented ssh.PublicKey) (bool, error) {
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
			if bytes.Equal(pub.Marshal(), presented.Marshal()) {
				return true, nil
			}
			b = rest
		}
	}
	return false, nil
}

func (s *Server) issueToken(ctx context.Context, username, userID string) (token string, sessionID string, err error) {
	if s.opts.LabMode {
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

func (s *Server) EnsureAuthorizedKeysDir() {
	_ = os.MkdirAll(s.opts.AuthorizedKeysDir, 0o700)
}

func (s *Server) SeedAuthorizedKey(username string, authorizedKeyLine string) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("username required")
	}
	line := strings.TrimSpace(authorizedKeyLine)
	if line == "" {
		return errors.New("authorized key required")
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line)); err != nil {
		return fmt.Errorf("invalid authorized key: %w", err)
	}

	if err := os.MkdirAll(s.opts.AuthorizedKeysDir, 0o700); err != nil {
		return err
	}
	dst := filepath.Join(s.opts.AuthorizedKeysDir, username+".pub")
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
