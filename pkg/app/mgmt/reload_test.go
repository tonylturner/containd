// SPDX-License-Identifier: Apache-2.0
package mgmtapp

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	engineapi "github.com/tonylturner/containd/api/engine"
	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/services"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestReloadActuallyReloadsEditedReferencedMaterial(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := config.NewSQLiteStore(filepath.Join(dir, "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	audits, err := audit.NewSQLiteStore(filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer audits.Close()
	cert, key, _ := sshTestKeyPair(t, dir, "site")
	observed := filepath.Join(dir, "observed.crt")
	t.Setenv("CONTAIND_RELOAD_TEST_CERT", cert)
	t.Setenv("CONTAIND_RELOAD_TEST_OBSERVED", observed)
	binary := filepath.Join(dir, "nginx")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nif [ \"$1\" = '-t' ]; then exit 0; fi\ncp \"$CONTAIND_RELOAD_TEST_CERT\" \"$CONTAIND_RELOAD_TEST_OBSERVED\"\nexec sleep 600\n"), 0700); err != nil {
		t.Fatal(err)
	}
	manager := services.NewManager(services.ManagerOptions{BaseDir: dir, SuperviseProxies: true, NginxPath: binary})
	manager.Proxy.CertsDir = dir
	manager.Syslog, manager.DNS, manager.NTP, manager.DHCP, manager.VPN = nil, nil, nil, nil, nil
	t.Cleanup(func() {
		if err := manager.Proxy.Apply(ctx, config.ProxyConfig{}); err != nil {
			t.Error(err)
		}
	})
	cfg := config.DefaultConfig()
	cfg.Interfaces = nil
	cfg.Services.Proxy.Reverse = config.ReverseProxyConfig{Enabled: true, Sites: []config.ReverseProxySite{{Name: "site", ListenPort: 8443, TLSEnabled: true, CertRef: "site", Backends: []string{"127.0.0.1:8080"}}}}
	if err := store.Save(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	baseline, err := store.ReadRunning(ctx)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Error(err)
			return
		}
		if r.URL.Path == "/health" {
			_, _ = io.WriteString(w, `{"bootId":"boot","iec104Enforcement":{}}`)
			return
		}
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()
	coordinator := mgmtTestCoordinator(t, store, engineapi.NewHTTPClient(server.URL), manager)
	if err := coordinator.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	waitObserved := func(want []byte) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for {
			got, err := os.ReadFile(observed)
			if err == nil && bytes.Equal(got, want) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("owner did not consume material: %v", err)
			}
			time.Sleep(time.Millisecond)
		}
	}
	old, err := os.ReadFile(cert)
	if err != nil {
		t.Fatal(err)
	}
	waitObserved(old)
	before := manager.Proxy.Status()["nginx_pid"]
	nextCert, nextKey, _ := sshTestKeyPair(t, dir, "next")
	fresh, err := os.ReadFile(nextCert)
	if err != nil {
		t.Fatal(err)
	}
	freshKey, err := os.ReadFile(nextKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cert, fresh, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, freshKey, 0600); err != nil {
		t.Fatal(err)
	}
	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core).Sugar()
	reloadRunningConfig(ctx, logger, coordinator, audits)
	waitObserved(fresh)
	if manager.Proxy.Status()["nginx_pid"] == before {
		t.Fatal("referenced certificate edit was adopted without reload")
	}
	after, err := store.ReadRunning(ctx)
	if err != nil || after.Running.RunningRevision != baseline.Running.RunningRevision {
		t.Fatalf("reload minted running revision: %v", err)
	}
	if err := os.WriteFile(cert, []byte("invalid certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	reloadRunningConfig(ctx, logger, coordinator, audits)
	if manager.Proxy.Status()["nginx_running"] != false {
		t.Fatal("invalid refreshed material left inherited runtime eligible")
	}
	if err := coordinator.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	for _, outcome := range manager.DeliveryOutcomes() {
		if outcome.Name == protection.SubsystemReverseProxy && (outcome.Fault == nil || outcome.Acknowledged != nil) {
			t.Fatalf("retry adopted stale referenced material: %+v", outcome)
		}
	}
	records, err := audits.List(ctx, 10)
	if err != nil || len(records) != 2 || records[0].Result != "failure" || records[1].Result != "success" || logs.FilterMessage("SIGHUP running configuration reload failed").Len() != 1 {
		t.Fatalf("reload audit: %+v %v", records, err)
	}
}
