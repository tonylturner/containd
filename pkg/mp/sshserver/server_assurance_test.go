// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package sshserver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"

	"github.com/tonylturner/containd/pkg/common/ratelimit"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/users"
)

// syncAuditStore is safe for the server's connection goroutines.
type syncAuditStore struct {
	mu      sync.Mutex
	records []audit.Record
}

func (s *syncAuditStore) Add(_ context.Context, r audit.Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, r)
	return nil
}

func (s *syncAuditStore) List(context.Context, int, ...int) ([]audit.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]audit.Record(nil), s.records...), nil
}

func (s *syncAuditStore) Close() error { return nil }

func (s *syncAuditStore) has(action, result, detail string) bool {
	records, _ := s.List(context.Background(), 0)
	for _, r := range records {
		if r.Action == action && r.Result == result && r.Source == "ssh" && strings.Contains(r.Detail, detail) {
			return true
		}
	}
	return false
}

// serveSSH runs srv on an ephemeral loopback port until the test ends.
func serveSSH(t *testing.T, srv *Server) string {
	t.Helper()
	srv.opts.ListenAddr = "127.0.0.1:0"
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("SSH server did not stop")
		}
	})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		srv.lnMu.Lock()
		ln := srv.ln
		srv.lnMu.Unlock()
		if ln != nil {
			return ln.Addr().String()
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("SSH listener unavailable")
	return ""
}

func newAssuranceServer(t *testing.T) (*Server, *users.SQLiteStore, *syncAuditStore) {
	t.Helper()
	srv, store, _ := newTestSSHServer(t)
	audits := &syncAuditStore{}
	srv.opts.AuditStore = audits
	return srv, store, audits
}

// kiPrompt records one keyboard-interactive round as the client saw it.
type kiPrompt struct {
	instruction string
	questions   []string
	echos       []bool
}

// scriptedKI answers each keyboard-interactive round with the next answer set.
type scriptedKI struct {
	mu      sync.Mutex
	answers [][]string
	prompts []kiPrompt
}

func (k *scriptedKI) method(retries int) ssh.AuthMethod {
	return ssh.RetryableAuthMethod(ssh.KeyboardInteractive(func(_, instruction string, questions []string, echos []bool) ([]string, error) {
		k.mu.Lock()
		defer k.mu.Unlock()
		k.prompts = append(k.prompts, kiPrompt{instruction: instruction, questions: questions, echos: echos})
		if len(k.answers) == 0 {
			return make([]string, len(questions)), nil
		}
		next := k.answers[0]
		k.answers = k.answers[1:]
		return next, nil
	}), retries)
}

func dialSSH(addr, user string, banners *[]string, methods ...ssh.AuthMethod) (*ssh.Client, error) {
	return ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            user,
		Auth:            methods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // local ephemeral test server
		BannerCallback: func(message string) error {
			if banners != nil {
				*banners = append(*banners, message)
			}
			return nil
		},
		Timeout: 3 * time.Second,
	})
}

// runShell opens the appliance CLI, sends input and returns its output.
func runShell(t *testing.T, client *ssh.Client, input string) string {
	t.Helper()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	var out bytes.Buffer
	session.Stdout = &out
	session.Stdin = strings.NewReader(input)
	if err := session.Shell(); err != nil {
		t.Fatal(err)
	}
	if err := session.Wait(); err != nil && !strings.Contains(err.Error(), "exited without exit status") {
		t.Fatal(err)
	}
	return out.String()
}

func clientKey(t *testing.T) (ssh.Signer, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
}

func createAdmin(t *testing.T, store *users.SQLiteStore, username string) (*users.User, string) {
	t.Helper()
	password := sshTestValue(username)
	u, err := store.Create(context.Background(), users.User{Username: username, Role: "admin"}, password)
	if err != nil {
		t.Fatal(err)
	}
	return u, password
}

func enrollTOTP(t *testing.T, store *users.SQLiteStore, userID, username string) string {
	t.Helper()
	enrollment, err := users.GenerateTOTPEnrollment(users.DefaultTOTPIssuer, username)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetTOTP(context.Background(), userID, enrollment.Secret); err != nil {
		t.Fatal(err)
	}
	return enrollment.Secret
}

func currentCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func TestSSHBootstrapAdminMustChangePassword(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "")
	srv, store, audits := newAssuranceServer(t)
	addr := serveSSH(t, srv)
	admin, err := store.GetByUsername(context.Background(), "containd")
	if err != nil || !admin.MustChangePassword {
		t.Fatalf("bootstrap admin = %+v, %v", admin, err)
	}
	earlier, err := store.CreateSession(context.Background(), admin.ID, time.Minute, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// Password alone never reaches the CLI while the change is pending.
	if client, err := dialSSH(addr, "containd", nil, ssh.Password("containd")); err == nil {
		_ = client.Close()
		t.Fatal("bootstrap password logged in without a password change")
	}

	fresh := sshTestValue("ssh-forced")
	ki := &scriptedKI{answers: [][]string{
		{"short", "short"},
		{fresh, fresh + "x"},
		{fresh, fresh},
	}}
	client, err := dialSSH(addr, "containd", nil, ssh.Password("containd"), ki.method(1))
	if err != nil {
		t.Fatalf("forced change login: %v", err)
	}
	defer client.Close()
	if len(ki.prompts) != 3 {
		t.Fatalf("prompts = %+v", ki.prompts)
	}
	for i, p := range ki.prompts {
		if strings.Join(p.questions, "|") != "New password: |Retype new password: " || p.echos[0] || p.echos[1] {
			t.Fatalf("round %d prompt = %+v", i, p)
		}
	}
	if !strings.Contains(ki.prompts[1].instruction, "Password not accepted: password must be at least 8 characters") ||
		!strings.Contains(ki.prompts[2].instruction, "do not match") {
		t.Fatalf("validation feedback missing: %+v", ki.prompts)
	}
	if out := runShell(t, client, "exit\n"); !strings.Contains(out, "containd# ") {
		t.Fatalf("CLI did not open after the change: %q", out)
	}

	changed, err := store.GetByID(context.Background(), admin.ID)
	if err != nil {
		t.Fatal(err)
	}
	if changed.MustChangePassword || bcrypt.CompareHashAndPassword([]byte(changed.PasswordHash), []byte(fresh)) != nil {
		t.Fatal("forced change did not store the new password and clear the flag")
	}
	if sess, err := store.GetSession(context.Background(), earlier.ID); err != nil || !sess.Revoked {
		t.Fatalf("earlier session survived the change: %+v, %v", sess, err)
	}
	if !audits.has("auth.password.change", "success", "forced change at ssh login") {
		t.Fatalf("missing change audit: %+v", audits.records)
	}

	// The new password now logs in directly; the bootstrap value no longer does.
	direct, err := dialSSH(addr, "containd", nil, ssh.Password(fresh))
	if err != nil {
		t.Fatalf("new password login: %v", err)
	}
	_ = direct.Close()
	if old, err := dialSSH(addr, "containd", nil, ssh.Password("containd")); err == nil {
		_ = old.Close()
		t.Fatal("bootstrap password still accepted")
	}
}

func TestSSHKeyLoginMustChangePasswordWithCurrentPassword(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "")
	srv, store, _ := newAssuranceServer(t)
	addr := serveSSH(t, srv)
	signer, line := clientKey(t)
	if err := srv.SeedAuthorizedKey("containd", line); err != nil {
		t.Fatal(err)
	}
	if client, err := dialSSH(addr, "containd", nil, ssh.PublicKeys(signer)); err == nil {
		_ = client.Close()
		t.Fatal("key login skipped the pending password change")
	}

	fresh := sshTestValue("key-forced")
	wrongCurrent := &scriptedKI{answers: [][]string{{"wrong", fresh, fresh}}}
	if client, err := dialSSH(addr, "containd", nil, ssh.PublicKeys(signer), wrongCurrent.method(1)); err == nil {
		_ = client.Close()
		t.Fatal("wrong current password changed the password")
	}
	ki := &scriptedKI{answers: [][]string{{"containd", fresh, fresh}}}
	client, err := dialSSH(addr, "containd", nil, ssh.PublicKeys(signer), ki.method(1))
	if err != nil {
		t.Fatalf("key login with change: %v", err)
	}
	defer client.Close()
	if len(ki.prompts) != 1 || ki.prompts[0].questions[0] != "Current password: " {
		t.Fatalf("prompts = %+v", ki.prompts)
	}
	admin, err := store.GetByUsername(context.Background(), "containd")
	if err != nil || admin.MustChangePassword {
		t.Fatalf("flag not cleared: %+v, %v", admin, err)
	}
}

func TestSSHPasswordLoginRequiresTOTP(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "")
	srv, store, audits := newAssuranceServer(t)
	srv.pwLimiter = ratelimit.NewAttemptLimiter(time.Minute, 2, time.Minute)
	addr := serveSSH(t, srv)
	u, password := createAdmin(t, store, "mfa-admin")
	secret := enrollTOTP(t, store, u.ID, u.Username)

	if client, err := dialSSH(addr, u.Username, nil, ssh.Password(password)); err == nil {
		_ = client.Close()
		t.Fatal("password alone logged in to an MFA account")
	}

	ki := &scriptedKI{answers: [][]string{{currentCode(t, secret)}}}
	client, err := dialSSH(addr, u.Username, nil, ssh.Password(password), ki.method(1))
	if err != nil {
		t.Fatalf("TOTP login: %v", err)
	}
	if len(ki.prompts) != 1 || strings.Join(ki.prompts[0].questions, "") != "Authentication code: " || ki.prompts[0].echos[0] {
		t.Fatalf("prompts = %+v", ki.prompts)
	}
	if out := runShell(t, client, "exit\n"); !strings.Contains(out, "containd# ") {
		t.Fatalf("CLI did not open: %q", out)
	}
	_ = client.Close()

	// Two wrong codes exhaust the limiter, which refuses the third attempt
	// before it prompts and then refuses the password too.
	wrong := &scriptedKI{answers: [][]string{{"000000"}, {"999999"}, {currentCode(t, secret)}}}
	if client, err := dialSSH(addr, u.Username, nil, ssh.Password(password), wrong.method(3)); err == nil {
		_ = client.Close()
		t.Fatal("wrong TOTP codes logged in")
	}
	if len(wrong.prompts) != 2 {
		t.Fatalf("prompts = %+v", wrong.prompts)
	}
	if !audits.has("ssh.login", "denied", "invalid totp code") {
		t.Fatalf("missing TOTP denial audit: %+v", audits.records)
	}
	blocked := &scriptedKI{answers: [][]string{{currentCode(t, secret)}}}
	if client, err := dialSSH(addr, u.Username, nil, ssh.Password(password), blocked.method(1)); err == nil {
		_ = client.Close()
		t.Fatal("rate-limited account logged in")
	}
}

func TestSSHKeyLoginSkipsTOTP(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "")
	srv, store, _ := newAssuranceServer(t)
	addr := serveSSH(t, srv)
	u, _ := createAdmin(t, store, "key-admin")
	enrollTOTP(t, store, u.ID, u.Username)
	signer, line := clientKey(t)
	if err := srv.SeedAuthorizedKey(u.Username, line); err != nil {
		t.Fatal(err)
	}
	client, err := dialSSH(addr, u.Username, nil, ssh.PublicKeys(signer))
	if err != nil {
		t.Fatalf("key login of an MFA account: %v", err)
	}
	_ = client.Close()
}

func TestSSHExpiredMFAGraceRefusesLogin(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "")
	srv, store, audits := newAssuranceServer(t)
	addr := serveSSH(t, srv)
	u, password := createAdmin(t, store, "grace-admin")
	past := time.Now().Add(-time.Hour)
	if err := store.SetMFARequirement(context.Background(), u.ID, true, &past); err != nil {
		t.Fatal(err)
	}
	signer, line := clientKey(t)
	if err := srv.SeedAuthorizedKey(u.Username, line); err != nil {
		t.Fatal(err)
	}
	for name, method := range map[string]ssh.AuthMethod{"password": ssh.Password(password), "key": ssh.PublicKeys(signer)} {
		var banners []string
		if client, err := dialSSH(addr, u.Username, &banners, method); err == nil {
			_ = client.Close()
			t.Fatalf("%s login succeeded after the MFA grace period", name)
		}
		if len(banners) != 2 || !strings.Contains(banners[1], "web UI to enroll") {
			t.Fatalf("%s banners = %q", name, banners)
		}
	}
	if !audits.has("ssh.login", "denied", "mfa setup required") {
		t.Fatalf("missing denial audit: %+v", audits.records)
	}

	// Within the grace period the account still logs in.
	future := time.Now().Add(time.Hour)
	if err := store.SetMFARequirement(context.Background(), u.ID, true, &future); err != nil {
		t.Fatal(err)
	}
	client, err := dialSSH(addr, u.Username, nil, ssh.Password(password))
	if err != nil {
		t.Fatalf("login within grace: %v", err)
	}
	_ = client.Close()
}

func TestSSHLabModeKeepsPasswordLogin(t *testing.T) {
	t.Run("pinned credential", func(t *testing.T) {
		t.Setenv("CONTAIND_LAB_MODE", "1")
		srv, _, _ := newAssuranceServer(t)
		srv.opts.LabMode = true
		addr := serveSSH(t, srv)
		client, err := dialSSH(addr, "containd", nil, ssh.Password("containd"))
		if err != nil {
			t.Fatalf("lab password login: %v", err)
		}
		defer client.Close()
		if out := runShell(t, client, "exit\n"); !strings.Contains(out, "containd# ") {
			t.Fatalf("lab login did not land in the CLI: %q", out)
		}
	})
	t.Run("account state ignored", func(t *testing.T) {
		t.Setenv("CONTAIND_LAB_MODE", "")
		srv, store, _ := newAssuranceServer(t)
		srv.opts.LabMode = true
		addr := serveSSH(t, srv)
		mfa, mfaPassword := createAdmin(t, store, "lab-mfa")
		enrollTOTP(t, store, mfa.ID, mfa.Username)
		expired, expiredPassword := createAdmin(t, store, "lab-grace")
		past := time.Now().Add(-time.Hour)
		if err := store.SetMFARequirement(context.Background(), expired.ID, true, &past); err != nil {
			t.Fatal(err)
		}
		for user, password := range map[string]string{"containd": "containd", mfa.Username: mfaPassword, expired.Username: expiredPassword} {
			client, err := dialSSH(addr, user, nil, ssh.Password(password))
			if err != nil {
				t.Fatalf("lab password login for %s: %v", user, err)
			}
			_ = client.Close()
		}
	})
}

func TestSSHCredentialChangeClosesOtherConnections(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "")
	password := sshTestValue("connections")
	t.Setenv("CONTAIND_DEFAULT_ADMIN_PASSWORD", password)
	srv, store, audits := newAssuranceServer(t)
	addr := serveSSH(t, srv)
	dial := func() *ssh.Client {
		client, err := dialSSH(addr, "containd", nil, ssh.Password(password))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })
		// An open channel means the connection's session is registered.
		idle, err := client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = idle.Close() })
		return client
	}
	other := dial()
	acting := dial()
	fresh := sshTestValue("menu-change")
	out := runShell(t, acting, "menu\n3\n"+fresh+"\n"+fresh+"\n0\n")
	if !strings.Contains(out, "Password updated.") {
		t.Fatalf("menu change failed: %q", out)
	}
	if !audits.has("auth.password.change", "success", "ssh menu") {
		t.Fatalf("missing menu audit: %+v", audits.records)
	}
	closed := make(chan error, 1)
	go func() { closed <- other.Wait() }()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("other SSH connection survived the password change")
	}
	if _, err := acting.NewSession(); err != nil {
		t.Fatalf("changing connection was closed: %v", err)
	}

	// A change from outside SSH, such as the web UI, closes every connection.
	admin, err := store.GetByUsername(context.Background(), "containd")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.DisableTOTP(context.Background(), admin.ID); err != nil {
		t.Fatal(err)
	}
	go func() { closed <- acting.Wait() }()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("SSH connection survived an MFA change from another session")
	}
}
