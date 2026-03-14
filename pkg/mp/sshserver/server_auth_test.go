// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package sshserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/ssh"

	"github.com/tonylturner/containd/pkg/cp/users"
)

type testConnMetadata struct {
	user string
}

func sshTestValue(label string) string {
	return label + "-Aa1!"
}

func (m testConnMetadata) User() string            { return m.user }
func (m testConnMetadata) SessionID() []byte       { return []byte("session") }
func (m testConnMetadata) ClientVersion() []byte   { return []byte("SSH-2.0-test-client") }
func (m testConnMetadata) ServerVersion() []byte   { return []byte("SSH-2.0-test-server") }
func (m testConnMetadata) RemoteAddr() net.Addr    { return &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 22} }
func (m testConnMetadata) LocalAddr() net.Addr     { return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2222} }

func TestNewValidatesRequiredOptions(t *testing.T) {
	t.Parallel()

	userStore, err := users.NewSQLiteStore(filepath.Join(t.TempDir(), "users.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer userStore.Close()

	base := Options{
		ListenAddr:        ":2222",
		BaseURL:           "http://127.0.0.1:8080",
		HostKeyPath:       filepath.Join(t.TempDir(), "host_key"),
		AuthorizedKeysDir: filepath.Join(t.TempDir(), "keys"),
		JWTSecret:         []byte(sshTestValue("jwt-signing")),
		UserStore:         userStore,
	}

	cases := []struct {
		name string
		opts Options
		want string
	}{
		{name: "missing listen addr", opts: Options{}, want: "listen addr required"},
		{name: "missing base url", opts: Options{ListenAddr: ":2222"}, want: "baseURL required"},
		{name: "missing user store", opts: Options{ListenAddr: ":2222", BaseURL: "http://127.0.0.1:8080"}, want: "user store required"},
		{name: "missing jwt secret", opts: Options{ListenAddr: ":2222", BaseURL: "http://127.0.0.1:8080", UserStore: userStore, HostKeyPath: "x", AuthorizedKeysDir: "y"}, want: "JWT secret required"},
		{name: "valid", opts: base, want: ""},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			srv, err := New(tc.opts)
			if tc.want == "" {
				if err != nil || srv == nil {
					t.Fatalf("New error = %v, server = %#v", err, srv)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("New error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestEnsureHostKeyAndAuthorizedKeys(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	hostKeyPath := filepath.Join(tmp, "ssh", "host_key")
	signer, err := ensureHostKey(hostKeyPath, 0)
	if err != nil {
		t.Fatalf("ensureHostKey: %v", err)
	}
	if signer == nil {
		t.Fatal("ensureHostKey returned nil signer")
	}
	signer2, err := ensureHostKey(hostKeyPath, 0)
	if err != nil || signer2 == nil {
		t.Fatalf("ensureHostKey second call: %v", err)
	}

	userStore, err := users.NewSQLiteStore(filepath.Join(tmp, "users.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer userStore.Close()
	srv, err := New(Options{
		ListenAddr:        ":2222",
		BaseURL:           "http://127.0.0.1:8080",
		HostKeyPath:       hostKeyPath,
		AuthorizedKeysDir: filepath.Join(tmp, "authorized_keys"),
		JWTSecret:         []byte(sshTestValue("jwt-signing")),
		UserStore:         userStore,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv.EnsureAuthorizedKeysDir()

	pub, line := authorizedKeyLineForTest(t)
	if err := srv.SeedAuthorizedKey("admin", line); err != nil {
		t.Fatalf("SeedAuthorizedKey: %v", err)
	}
	if err := srv.SeedAuthorizedKey("admin", line); err != nil {
		t.Fatalf("SeedAuthorizedKey duplicate: %v", err)
	}
	ok, err := isAuthorizedKey(srv.opts.AuthorizedKeysDir, "admin", pub)
	if err != nil {
		t.Fatalf("isAuthorizedKey: %v", err)
	}
	if !ok {
		t.Fatal("expected authorized key to be accepted")
	}
}

func TestIssueTokenAndSignJWT(t *testing.T) {
	t.Parallel()

	userStore, err := users.NewSQLiteStore(filepath.Join(t.TempDir(), "users.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer userStore.Close()
	if err := userStore.EnsureDefaultAdmin(context.Background()); err != nil {
		t.Fatalf("EnsureDefaultAdmin: %v", err)
	}

	srv, err := New(Options{
		ListenAddr:        ":2222",
		BaseURL:           "http://127.0.0.1:8080",
		HostKeyPath:       filepath.Join(t.TempDir(), "host_key"),
		AuthorizedKeysDir: filepath.Join(t.TempDir(), "keys"),
		JWTSecret:         []byte(sshTestValue("jwt-signing")),
		UserStore:         userStore,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	admin, err := userStore.GetByUsername(context.Background(), "containd")
	if err != nil || admin == nil {
		t.Fatalf("GetByUsername: %v, admin=%#v", err, admin)
	}
	token, sessionID, err := srv.issueToken(context.Background(), admin.Username, admin.ID)
	if err != nil {
		t.Fatalf("issueToken: %v", err)
	}
	if sessionID == "" || token == "" {
		t.Fatalf("unexpected token/session: %q %q", token, sessionID)
	}
	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
		return []byte(sshTestValue("jwt-signing")), nil
	})
	if err != nil || !parsed.Valid {
		t.Fatalf("ParseWithClaims: parsed=%v err=%v", parsed != nil && parsed.Valid, err)
	}
	if claims["sub"] != admin.ID || claims["username"] != admin.Username {
		t.Fatalf("unexpected claims: %#v", claims)
	}

	if _, _, err := srv.issueToken(context.Background(), admin.Username, "wrong-id"); err == nil {
		t.Fatal("expected user mismatch error")
	}

	labServer, err := New(Options{
		ListenAddr:        ":2222",
		BaseURL:           "http://127.0.0.1:8080",
		HostKeyPath:       filepath.Join(t.TempDir(), "host_key_lab"),
		AuthorizedKeysDir: filepath.Join(t.TempDir(), "keys_lab"),
		LabMode:           true,
		UserStore:         userStore,
	})
	if err != nil {
		t.Fatalf("New lab server: %v", err)
	}
	token, sessionID, err = labServer.issueToken(context.Background(), admin.Username, admin.ID)
	if err != nil {
		t.Fatalf("lab issueToken: %v", err)
	}
	if token != "lab" || sessionID != "" {
		t.Fatalf("unexpected lab token/session: %q %q", token, sessionID)
	}

	signed, err := signJWT([]byte(sshTestValue("jwt-signing")), admin.ID, admin.Username, admin.Role, "jti-test", time.Now().Add(time.Minute))
	if err != nil || signed == "" {
		t.Fatalf("signJWT: token=%q err=%v", signed, err)
	}
}

func TestPasswordAndPublicKeyCallbacks(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	userStore, err := users.NewSQLiteStore(filepath.Join(tmp, "users.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer userStore.Close()
	if err := userStore.EnsureDefaultAdmin(context.Background()); err != nil {
		t.Fatalf("EnsureDefaultAdmin: %v", err)
	}
	viewerPassword := sshTestValue("viewer-login")
	if _, err := userStore.Create(context.Background(), users.User{Username: "viewer", Role: "view"}, viewerPassword); err != nil {
		t.Fatalf("Create viewer: %v", err)
	}

	srv, err := New(Options{
		ListenAddr:        ":2222",
		BaseURL:           "http://127.0.0.1:8080",
		HostKeyPath:       filepath.Join(tmp, "host_key"),
		AuthorizedKeysDir: filepath.Join(tmp, "keys"),
		JWTSecret:         []byte(sshTestValue("jwt-signing")),
		UserStore:         userStore,
		AllowPassword:     true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	pwcb := srv.passwordCallback()
	perms, err := pwcb(testConnMetadata{user: "containd"}, []byte("containd"))
	if err != nil || perms == nil {
		t.Fatalf("passwordCallback admin error=%v perms=%#v", err, perms)
	}
	if _, err := pwcb(testConnMetadata{user: "viewer"}, []byte(viewerPassword)); err == nil {
		t.Fatal("expected non-admin ssh password auth to be rejected")
	}
	if _, err := pwcb(testConnMetadata{user: "containd"}, []byte("wrong")); err == nil {
		t.Fatal("expected wrong password to be rejected")
	}

	pub, line := authorizedKeyLineForTest(t)
	if err := srv.SeedAuthorizedKey("containd", line); err != nil {
		t.Fatalf("SeedAuthorizedKey: %v", err)
	}
	pkcb := srv.publicKeyCallback()
	perms, err = pkcb(testConnMetadata{user: "containd"}, pub)
	if err != nil || perms == nil {
		t.Fatalf("publicKeyCallback admin error=%v perms=%#v", err, perms)
	}
	if _, err := pkcb(testConnMetadata{user: "viewer"}, pub); err == nil {
		t.Fatal("expected non-admin ssh public key auth to be rejected")
	}
}

func authorizedKeyLineForTest(t *testing.T) (ssh.PublicKey, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	return pub, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
}
