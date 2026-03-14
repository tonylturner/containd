// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/users"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
)

type dashboardServices struct {
	status any
	events []dpevents.Event
}

func (m *dashboardServices) Apply(ctx context.Context, cfg config.ServicesConfig) error {
	return nil
}

func (m *dashboardServices) Status() any {
	return m.status
}

func (m *dashboardServices) RecentEvents(limit int) []dpevents.Event {
	return append([]dpevents.Event(nil), m.events...)
}

type mockAuditStore struct {
	records []audit.Record
	err     error
}

func (m *mockAuditStore) Add(ctx context.Context, r audit.Record) error {
	m.records = append(m.records, r)
	return nil
}

func (m *mockAuditStore) List(ctx context.Context, limit int, offset ...int) ([]audit.Record, error) {
	if m.err != nil {
		return nil, m.err
	}
	return append([]audit.Record(nil), m.records...), nil
}

func (m *mockAuditStore) Close() error { return nil }

func generateTestCertPEM(t *testing.T) (string, string) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	templ := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "containd.local",
			Organization: []string{"containd test"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		DNSNames:              []string{"containd.local", "lab.containd.local"},
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, templ, templ, pub, priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return string(certPEM), string(keyPEM)
}

func TestDashboardHandlerAndHelpers(t *testing.T) {
	t.Setenv("CONTAIND_LAB_MODE", "1")

	cfg := config.DefaultConfig()
	cfg.Assets = []config.Asset{{Name: "plc-1"}}
	cfg.Zones = []config.Zone{{Name: "wan"}, {Name: "dmz"}}
	cfg.Interfaces = []config.Interface{{Name: "wan"}, {Name: "dmz"}}
	cfg.Firewall.Rules = []config.Rule{
		{ID: "rule-1", Action: config.ActionAllow},
		{ID: "rule-2", Action: config.ActionAllow, ICS: config.ICSPredicate{Protocol: "modbus"}},
	}
	store := &mockStore{cfg: cfg}

	userStore := newMockUserStore()
	created, err := userStore.Create(context.Background(), users.User{Username: "admin", Role: "admin"}, testPassword)
	if err != nil {
		t.Fatalf("Create(user): %v", err)
	}

	engine := newRuntimeMockEngine()
	engine.eventsResp = []dpevents.Event{
		{Proto: "ids", Kind: "alert"},
		{Proto: "modbus", Kind: "request", Attributes: map[string]any{"is_write": true}},
	}
	services := &dashboardServices{
		status: map[string]any{"proxy": map[string]any{"enabled": true}},
		events: []dpevents.Event{
			{Kind: "service.av.detected"},
			{Kind: "service.av.block_flow"},
		},
	}
	auditStore := &mockAuditStore{records: []audit.Record{
		{Actor: "system", Action: "ignored"},
		{Actor: "alice", Action: "commit", Result: "success"},
	}}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(ctxUserKey, created.ID)
		c.Next()
	})
	router.GET("/dashboard", dashboardHandler(store, engine, services, userStore, auditStore))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("dashboard status = %d, body=%s", rec.Code, rec.Body.String())
	}

	var resp dashboardResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal(dashboard): %v", err)
	}
	if resp.Health.Status != "ok" || !resp.Health.LabMode {
		t.Fatalf("unexpected health: %#v", resp.Health)
	}
	if resp.Counts.Assets != 1 || resp.Counts.Zones != 2 || resp.Counts.Interfaces != 2 || resp.Counts.Rules != 2 || resp.Counts.ICSRules != 1 {
		t.Fatalf("unexpected counts: %#v", resp.Counts)
	}
	if resp.EventStats.Total != 4 || resp.EventStats.IDSAlerts != 1 || resp.EventStats.ModbusWrites != 1 || resp.EventStats.AVDetections != 1 || resp.EventStats.AVBlocks != 1 {
		t.Fatalf("unexpected event stats: %#v", resp.EventStats)
	}
	if resp.LastActivity == nil || resp.LastActivity.Actor != "alice" {
		t.Fatalf("unexpected last activity: %#v", resp.LastActivity)
	}
	userMap, ok := resp.User.(map[string]any)
	if !ok || userMap["username"] != "admin" {
		t.Fatalf("unexpected user payload: %#v", resp.User)
	}
	if servicesMap, ok := resp.Services.(map[string]any); !ok || servicesMap["proxy"] == nil {
		t.Fatalf("unexpected services payload: %#v", resp.Services)
	}

	if !modbusWriteEvent(dpevents.Event{Attributes: map[string]any{"is_write": true}}) {
		t.Fatal("modbusWriteEvent(true) should be true")
	}
	if modbusWriteEvent(dpevents.Event{Attributes: map[string]any{"is_write": "nope"}}) {
		t.Fatal("modbusWriteEvent(non-bool) should be false")
	}
}

func TestSystemTLSHandlersAndHelpers(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := generateTestCertPEM(t)
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	if err := os.WriteFile(certPath, []byte(certPEM), 0o644); err != nil {
		t.Fatalf("WriteFile(cert): %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0o600); err != nil {
		t.Fatalf("WriteFile(key): %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.System.Mgmt.HTTPListenAddr = ":8081"
	cfg.System.Mgmt.HTTPSListenAddr = ":8443"
	truth := true
	cfg.System.Mgmt.EnableHTTP = &truth
	cfg.System.Mgmt.EnableHTTPS = &truth
	cfg.System.Mgmt.TLSCertFile = certPath
	cfg.System.Mgmt.TLSKeyFile = keyPath

	store := &mockStore{cfg: cfg}
	router := gin.New()
	router.GET("/system/tls", getTLSHandler(store))
	router.POST("/system/tls/cert", setTLSCertHandler(store))
	router.POST("/system/tls/trusted-ca", setTrustedCAHandler(store))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/system/tls", nil)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("getTLS status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var info tlsInfoResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil {
		t.Fatalf("json.Unmarshal(tlsInfo): %v", err)
	}
	if info.HTTPListenAddr != ":8081" || info.CertSubject == "" || len(info.CertDNSNames) != 2 {
		t.Fatalf("unexpected tls info response: %#v", info)
	}

	invalidPairJSON, err := json.Marshal(map[string]string{
		"certPEM": strings.TrimSpace(certPEM),
		"keyPEM":  "not-a-key",
	})
	if err != nil {
		t.Fatalf("json.Marshal(invalidPairJSON): %v", err)
	}
	invalidPairBody := bytes.NewBuffer(invalidPairJSON)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/system/tls/cert", invalidPairBody)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid cert/key pair") {
		t.Fatalf("setTLSCert invalid status/body = %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/system/tls/trusted-ca", bytes.NewBufferString(`{"pem":"not pem"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid PEM") {
		t.Fatalf("setTrustedCA invalid status/body = %d %s", rec.Code, rec.Body.String())
	}

	if _, err := readAnyPEM(certPEM); err != nil {
		t.Fatalf("readAnyPEM(valid): %v", err)
	}
	if got, ok := parseDockerBindMount("/host/path:/container/path:ro"); !ok || got.Mode != "ro" {
		t.Fatalf("parseDockerBindMount(valid) = %#v, %v", got, ok)
	}
	if _, ok := parseDockerBindMount("invalid"); ok {
		t.Fatal("parseDockerBindMount(invalid) should fail")
	}
}

func TestSystemInspectionAndFactoryResetHandlers(t *testing.T) {
	inspect := map[string]interface{}{
		"Id": "1234567890abcdef",
		"Config": map[string]interface{}{
			"Image": "ghcr.io/example/containd:test",
			"Env": []interface{}{
				"CONTAIND_IMAGE=ghcr.io/example/containd:test",
				"PATH=/usr/bin",
				"SECRET_TOKEN=hidden",
			},
		},
		"HostConfig": map[string]interface{}{
			"NetworkMode":    "host",
			"Privileged":     true,
			"ReadonlyRootfs": true,
			"RestartPolicy":  map[string]interface{}{"Name": "unless-stopped"},
			"SecurityOpt":    []interface{}{"no-new-privileges", "seccomp=runtime/default", "apparmor=containd-profile"},
			"CapAdd":         []interface{}{"CAP_NET_ADMIN"},
			"Binds":          []interface{}{"/host/data:/data:rw"},
		},
		"RestartCount":    float64(3),
		"AppArmorProfile": "fallback-profile",
	}
	ci := parseDockerInspect(inspect)
	if ci.ID != "1234567890ab" || ci.Image != "ghcr.io/example/containd:test" || ci.RestartPolicy != "unless-stopped" || !ci.NoNewPrivileges || ci.ApparmorProfile != "containd-profile" || ci.RestartCount != 3 {
		t.Fatalf("unexpected parsed docker inspect container info: %#v", ci)
	}
	if len(ci.EnvVars) != 2 || len(ci.Mounts) != 1 || len(ci.Capabilities) != 1 {
		t.Fatalf("unexpected filtered inspect values: %#v", ci)
	}
	if !isVirtualFS("proc") || isVirtualFS("ext4") {
		t.Fatal("isVirtualFS classification mismatch")
	}
	if !isEnvSafe("CONTAIND_ALLOWED_ORIGINS") || !isEnvSafe("PATH") || isEnvSafe("SECRET_TOKEN") {
		t.Fatal("isEnvSafe classification mismatch")
	}

	dir := t.TempDir()
	cfgStore, err := config.NewSQLiteStore(filepath.Join(dir, "config.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore(config): %v", err)
	}
	defer cfgStore.Close()
	userStore, err := users.NewSQLiteStore(filepath.Join(dir, "users.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore(users): %v", err)
	}
	defer userStore.Close()
	auditStore, err := audit.NewSQLiteStore(filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStore(audit): %v", err)
	}
	defer auditStore.Close()

	ctx := context.Background()
	initialCfg := config.DefaultConfig()
	initialCfg.System.Hostname = "before-reset"
	if err := cfgStore.Save(ctx, initialCfg); err != nil {
		t.Fatalf("cfgStore.Save(initial): %v", err)
	}
	if err := userStore.EnsureDefaultAdmin(ctx); err != nil {
		t.Fatalf("EnsureDefaultAdmin: %v", err)
	}
	admin, err := userStore.GetByUsername(ctx, "containd")
	if err != nil {
		t.Fatalf("GetByUsername(containd): %v", err)
	}
	sess, err := userStore.CreateSession(ctx, admin.ID, time.Hour, 2*time.Hour)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if err := auditStore.Add(ctx, audit.Record{Actor: "alice", Action: "pre.reset", Result: "success"}); err != nil {
		t.Fatalf("auditStore.Add: %v", err)
	}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(ctxSessionKey, sess.ID)
		c.Set("auditStore", auditStore)
		c.Set("actor", "alice")
		c.Next()
	})
	router.POST("/system/factory-reset", factoryResetHandler(cfgStore, userStore))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/system/factory-reset", bytes.NewBufferString(`{"confirm":"NUCLEAR"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("factory reset status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if cookie := rec.Header().Get("Set-Cookie"); !strings.Contains(cookie, "containd_token=") {
		t.Fatalf("expected cleared auth cookie, got %q", cookie)
	}

	if revoked, err := userStore.GetSession(ctx, sess.ID); err == nil || revoked != nil {
		t.Fatalf("expected wiped session after reset, got sess=%#v err=%v", revoked, err)
	}
	admin, err = userStore.GetByUsername(ctx, "containd")
	if err != nil || !admin.MustChangePassword {
		t.Fatalf("expected reset default admin, got user=%#v err=%v", admin, err)
	}
	resetCfg, err := cfgStore.Load(ctx)
	if err != nil {
		t.Fatalf("cfgStore.Load(after reset): %v", err)
	}
	if resetCfg.System.Hostname != "containd" || resetCfg.System.Mgmt.HTTPListenAddr != ":8080" || resetCfg.System.Mgmt.HTTPSListenAddr != ":8443" {
		t.Fatalf("unexpected reset config: %#v", resetCfg.System.Mgmt)
	}
	records, err := auditStore.List(ctx, 10)
	if err != nil {
		t.Fatalf("auditStore.List(after reset): %v", err)
	}
	if len(records) != 1 || records[0].Action != "system.factory_reset.completed" {
		t.Fatalf("unexpected post-reset audit records: %#v", records)
	}
}
