// SPDX-License-Identifier: Apache-2.0

package mgmtapp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/mgmttls"
	"github.com/tonylturner/containd/pkg/common/profile"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// Alternate profiles require a fresh process: Load is immutable by contract.
func TestStrictManagement(t *testing.T) {
	if os.Getenv("CONTAIND_TEST_STRICT_MGMT") != "1" {
		runStrictManagementTest(t, "")
		return
	}
	if _, err := profile.Load(); err != nil || !profile.IsStrict() {
		t.Fatalf("strict profile not loaded: %v", err)
	}
	t.Run("ProjectionAndHTTPSOnly", testStrictProjectionAndHTTPSOnly)
	t.Run("HTTPSIdentityRefusal", testStrictHTTPSIdentityRefusal)
	t.Run("ListenerRecovery", testStrictListenerRecovery)
	t.Run("Hints", testStrictHints)
	t.Run("SSHRuntimePolicy", testStrictSSHRuntimePolicy)
	t.Run("BootAudit", testStrictBootAudit)
}

func runStrictManagementTest(t *testing.T, subtest string) {
	t.Helper()
	pattern := "^TestStrictManagement$"
	if subtest != "" {
		pattern += "/^" + subtest + "$"
	}
	cmd := exec.Command(os.Args[0], "-test.run="+pattern, "-test.v")
	cmd.Env = append(os.Environ(), "CONTAIND_TEST_STRICT_MGMT=1", "CONTAIND_PROFILE=strict")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("strict subprocess: %v\n%s", err, output)
	}
}

func testStrictProjectionAndHTTPSOnly(t *testing.T) {
	dir := t.TempDir()
	cert, key, _ := sshTestKeyPair(t, dir, "server")
	saved := config.DefaultConfig()
	saved.System.Mgmt.EnableHTTP = new(true)
	saved.System.Mgmt.EnableHTTPS = new(false)
	saved.System.Mgmt.EnableHSTS = new(false)
	saved.System.Mgmt.RedirectHTTPToHTTPS = new(true)
	saved.System.Mgmt.HTTPListenAddr = "127.0.0.1:0"
	saved.System.Mgmt.HTTPSListenAddr = "127.0.0.1:0"
	saved.System.Mgmt.TLSCertFile, saved.System.Mgmt.TLSKeyFile = cert, key
	saved.System.SSH.ShellMode = "linux"
	effective, overrides := config.ProjectProfile(saved, profile.IsStrict())
	if len(overrides) != 4 {
		t.Fatalf("overrides: %+v", overrides)
	}
	lc, err := resolveMgmtListenerConfig(zap.NewNop().Sugar(), effective, nil)
	if err != nil {
		t.Fatal(err)
	}
	if lc.enableHTTP || !lc.enableHTTPS || !lc.enableHSTS {
		t.Fatalf("strict listener policy: %+v", lc)
	}
	binds, err := buildMgmtServers(http.NewServeMux(), lc)
	if err != nil {
		t.Fatal(err)
	}
	defer binds.close()
	if binds.http.record().Enabled || binds.redirects || !binds.https.record().Enabled {
		t.Fatalf("strict bound plaintext or redirects: %+v", binds.record())
	}
	if !*saved.System.Mgmt.EnableHTTP || *saved.System.Mgmt.EnableHTTPS || *saved.System.Mgmt.EnableHSTS || saved.System.SSH.ShellMode != "linux" {
		t.Fatal("projection changed saved intent")
	}
}

func testStrictHTTPSIdentityRefusal(t *testing.T) {
	for _, tc := range []struct {
		name    string
		corrupt bool
		sanless bool
		missing bool
	}{
		{name: "missing external identity", missing: true},
		{name: "corrupt external identity", corrupt: true},
		{name: "SAN-less external identity", sanless: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			saved := config.DefaultConfig()
			if tc.missing {
				t.Setenv("CONTAIND_TLS_CERT_FILE", filepath.Join(dir, "missing.crt"))
				t.Setenv("CONTAIND_TLS_KEY_FILE", filepath.Join(dir, "missing.key"))
			} else {
				cert, key := tlsCertificate(t, tc.sanless)
				certFile, keyFile := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
				if tc.corrupt {
					cert = []byte("corrupt")
					key = []byte("corrupt")
				}
				if err := os.WriteFile(certFile, cert, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(keyFile, key, 0o600); err != nil {
					t.Fatal(err)
				}
				saved.System.Mgmt.TLSCertFile, saved.System.Mgmt.TLSKeyFile = certFile, keyFile
			}
			effective, _ := config.ProjectProfile(saved, true)
			_, err := resolveMgmtListenerConfig(zap.NewNop().Sugar(), effective, nil)
			if err == nil || !strings.HasPrefix(err.Error(), "CONTAIND_PROFILE=strict refuses to start without HTTPS: ") {
				t.Fatalf("strict identity failure = %v", err)
			}
			if tc.sanless && !strings.Contains(err.Error(), "subject alternative name") {
				t.Fatalf("SAN-less strict refusal omitted its reason: %v", err)
			}
			t.Setenv("CONTAIND_TLS_CERT_FILE", "")
			t.Setenv("CONTAIND_TLS_KEY_FILE", "")
		})
	}
}

func tlsCertificate(t *testing.T, sanless bool) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(41),
		Subject:      pkix.Name{CommonName: "strict-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if !sanless {
		template.DNSNames = []string{"strict-test"}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func TestLegacyTLSSubjectAltNamePolicy(t *testing.T) {
	leaf := &x509.Certificate{Subject: pkix.Name{CommonName: "legacy-management"}}
	core, logs := observer.New(zapcore.WarnLevel)
	logger := zap.New(core).Sugar()
	if err := checkManagementTLSSubjectAltName(logger, "/data/tls/server.pem", leaf, false); err != nil {
		t.Fatalf("training rejected a legacy identity: %v", err)
	}
	if logs.Len() != 1 || !strings.Contains(logs.All()[0].Message, "/data/tls/server.pem") ||
		!strings.Contains(logs.All()[0].Message, "subject alternative name") ||
		!strings.Contains(logs.All()[0].Message, "-addext") {
		t.Fatalf("training warning lacks certificate and fix: %+v", logs.All())
	}
	if err := checkManagementTLSSubjectAltName(logger, "/data/tls/server.pem", leaf, true); err == nil ||
		!strings.Contains(err.Error(), "subject alternative name") || logs.Len() != 1 {
		t.Fatalf("strict policy did not refuse without logging a training warning: err=%v logs=%+v", err, logs.All())
	}
}

func testStrictListenerRecovery(t *testing.T) {
	stores, saved := bootStores(t, ":8080")
	saved.System.Mgmt.HTTPSListenAddr = "192.0.2.50:9443"
	effective, _ := config.ProjectProfile(saved, true)
	lc, err := resolveMgmtListenerConfig(zap.NewNop().Sugar(), effective, nil)
	if err != nil {
		t.Fatal(err)
	}
	bindErr := errors.New("HTTPS address unavailable")
	for _, failAll := range []bool{false, true} {
		builds := &listenerBuilds{t: t, bindErr: bindErr, failAll: failAll}
		bound, err := bindManagement(zap.NewNop().Sugar(), stores, effective, nil, lc, builds.build)
		if len(builds.built) != 2 {
			t.Fatalf("want configured then default HTTPS attempt: %d, %v", len(builds.built), err)
		}
		for _, built := range builds.built {
			if built.enableHTTP || !built.enableHTTPS || !built.enableHSTS {
				t.Fatalf("recovery relaxed strict policy: %+v", built)
			}
		}
		if failAll {
			if err == nil || !strings.HasPrefix(err.Error(), "CONTAIND_PROFILE=strict refuses to start without HTTPS: ") || !errors.Is(err, bindErr) {
				t.Fatalf("strict bind refusal: %v", err)
			}
		} else if err != nil || bound.cfg.System.SSH.ShellMode != "appliance" || bound.event == nil {
			t.Fatalf("strict HTTPS fallback failed: %+v, %v", bound, err)
		}
	}
}

func testStrictHints(t *testing.T) {
	t.Setenv("CONTAIND_USERS_DB", filepath.Join(t.TempDir(), "users.db"))
	core, logs := observer.New(zapcore.InfoLevel)
	printStartupHints(zap.New(core).Sugar(), ":8080", "", ":8443", "", false, true, ":2222", true)
	if logs.FilterMessageSnippet("password=containd").Len() != 0 || logs.FilterMessageSnippet("UI/API (HTTP):").Len() != 0 {
		t.Fatal("strict hints advertise training access")
	}
	if logs.FilterMessageSnippet("profile=strict").Len() != 1 || logs.FilterMessageSnippet(bootstrapPasswordPath(usersDBPath())).Len() != 1 {
		t.Fatal("strict hints missing profile or password delivery path")
	}
}

func testStrictSSHRuntimePolicy(t *testing.T) {
	stores, saved := bootStores(t, ":8080")
	saved.System.SSH.ShellMode = "linux"
	t.Setenv(config.EnvSSHShellMode, "linux") // defense in depth beyond preflight
	rt := resolveSSHRuntimeConfig(saved)
	if rt.shellMode != "appliance" || rt.shellModeSource != "profile (strict)" {
		t.Fatalf("SSH policy: %+v", rt)
	}
	configureSSHPolicy(stores.store, stores.userStore, rt)
	policy, err := stores.store.(*config.SQLiteStore).SSHRuntimePolicy(context.Background())
	if err != nil || policy.ShellMode != "appliance" || policy.ShellModeSource != config.SSHShellModeSourceProfile {
		t.Fatalf("published SSH policy: %+v, %v", policy, err)
	}
}

func testStrictBootAudit(t *testing.T) {
	store, err := audit.NewSQLiteStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	saved := config.DefaultConfig()
	saved.System.Mgmt.EnableHTTPS = new(false)
	saved.System.SSH.ShellMode = "linux"
	_, overrides := config.ProjectProfile(saved, true)
	core, logs := observer.New(zapcore.InfoLevel)
	if err := recordProfileBoot(zap.New(core).Sugar(), store, overrides); err != nil {
		t.Fatal(err)
	}
	records, err := store.List(context.Background(), 100)
	if err != nil || len(records) != 1 {
		t.Fatalf("want a single boot profile record: %+v, %v", records, err)
	}
	rec := records[0]
	if rec.Action != "management.profile" || rec.Actor != "system" || rec.Result != "started" ||
		!strings.Contains(rec.Detail, "profile=strict; overrides=") ||
		!strings.Contains(rec.Detail, "system.ssh.shellMode=linux->appliance") ||
		!strings.Contains(rec.Detail, "system.mgmt.enableHTTPS=false->true") ||
		logs.Len() != len(overrides) {
		t.Fatalf("profile evidence mismatch: %+v, %+v", rec, logs.All())
	}
}

func TestTLSFingerprintBootAndReload(t *testing.T) {
	dir := t.TempDir()
	cert, key, _ := sshTestKeyPair(t, dir, "server")
	loader := newCertReloader(cert, key)
	if _, err := loader.GetCertificate(nil); err != nil {
		t.Fatal(err)
	}
	first := mgmttls.Fingerprint(loader.LastLeaf())
	core, logs := observer.New(zapcore.InfoLevel)
	notifications := 0
	observeTLSIdentity(zap.New(core).Sugar(), loader, func() { notifications++ })
	if logs.Len() != 1 || !strings.HasPrefix(logs.All()[0].Message, "management TLS certificate sha256="+first+" subject=") || !strings.Contains(logs.All()[0].Message, " notAfter=") {
		t.Fatalf("missing boot fingerprint: %+v", logs.All())
	}
	sshTestKeyPair(t, dir, "server")
	if _, err := loader.GetCertificate(nil); err != nil {
		t.Fatal(err)
	}
	second := mgmttls.Fingerprint(loader.LastLeaf())
	if first == second || notifications != 1 || logs.Len() != 2 || !strings.Contains(logs.All()[1].Message, "sha256="+second) {
		t.Fatalf("missing reload fingerprint: %+v", logs.All())
	}
	if err := os.WriteFile(cert, []byte("corrupted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loader.GetCertificate(nil); err != nil {
		t.Fatal("last-good certificate was not retained", err)
	}
	if notifications != 1 || logs.Len() != 2 || mgmttls.Fingerprint(loader.LastLeaf()) != second {
		t.Fatal("rejected reload changed the logged/served identity")
	}
}

func TestTrainingProfileBootAudit(t *testing.T) {
	store, err := audit.NewSQLiteStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := recordProfileBoot(zap.NewNop().Sugar(), store, nil); err != nil {
		t.Fatal(err)
	}
	records, err := store.List(context.Background(), 100)
	if err != nil || len(records) != 1 || records[0].Action != "management.profile" || records[0].Detail != "profile=training; overrides=none" {
		t.Fatalf("training profile audit: %+v, %v", records, err)
	}
}
