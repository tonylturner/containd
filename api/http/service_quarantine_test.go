// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/services"
)

func TestServiceQuarantinePreviews(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Services.Proxy.Forward.Upstream = "legacy"
	store := &mockStore{cfg: cfg}
	engine := &rulesetPreviewEngine{mockEngine: &mockEngine{}}
	for _, handler := range []gin.HandlerFunc{getRulesetPreviewHandler(store, engine), getICSCoverageHandler(store, engine)} {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
		handler(c)
		var out struct {
			Faults []services.ServiceFault `json:"serviceFaults"`
		}
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil || len(out.Faults) != 1 || out.Faults[0].Service != "proxy" {
			t.Fatalf("preview did not disclose quarantine: %d %s", rec.Code, rec.Body)
		}
	}
	if engine.cfg.Services.Proxy.Forward.Upstream != "" || cfg.Services.Proxy.Forward.Upstream != "legacy" {
		t.Fatal("preview did not project without mutation")
	}
}

func TestServiceQuarantineReplayAndStatus(t *testing.T) {
	for _, materialFault := range []bool{false, true} {
		t.Run(map[bool]string{false: "stored", true: "material"}[materialFault], func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.Services.AV.Mode = "bad"
			cfg.Services.AV.Enabled = true
			cfg.Services.VPN.WireGuard.ListenInterfaces = []string{"missing"}
			if materialFault {
				cfg.Services.Proxy.Reverse.Enabled = true
				cfg.Services.Proxy.Reverse.Sites = []config.ReverseProxySite{{
					Name: "app", ListenPort: 443, TLSEnabled: true, CertRef: "missing",
					Backends: []string{"127.0.0.1:80"},
				}}
			} else {
				cfg.Services.Proxy.Forward.Upstream = "legacy"
			}
			m := services.NewManager(services.ManagerOptions{BaseDir: t.TempDir()})
			m.Syslog, m.DNS, m.NTP, m.DHCP, m.VPN = nil, nil, nil, nil, nil
			m.Proxy.CertsDir = filepath.Join(t.TempDir(), "missing")
			engine := &mockEngine{}
			warnings, err := applyConfigSnapshot(context.Background(), &mockStore{cfg: cfg}, engine, m, nil, cfg)
			if err != nil || !engine.applied || len(warnings) == 0 {
				t.Fatalf("quarantine blocked firewall: %v %v", err, warnings)
			}
			if engine.lastSvc.VPN.WireGuard.Enabled || engine.lastSvc.Proxy.Reverse.Enabled || !engine.lastSvc.AV.BackendDisabled {
				t.Fatalf("engine received desired, not effective, services: %+v", engine.lastSvc)
			}
			// Desired state is retained for export and repair.
			if cfg.Services.AV.Mode != "bad" || len(cfg.Services.VPN.WireGuard.ListenInterfaces) == 0 {
				t.Fatal("runtime persisted or mutated quarantine")
			}
			server := NewServerWithEngineAndServices(&mockStore{cfg: cfg}, nil, &mockEngine{avErr: errors.New("offline")}, m, newMockUserStore())
			rec := httptest.NewRecorder()
			server.ServeHTTP(rec, authedRequest(http.MethodGet, "/api/v1/services/status", nil))
			var out struct {
				Faults []services.ServiceFault `json:"faults"`
				AV     struct {
					Available bool                  `json:"available"`
					State     string                `json:"state"`
					Fault     services.ServiceFault `json:"fault"`
					Error     string                `json:"error"`
				} `json:"av"`
			}
			if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil ||
				len(out.Faults) != 3 || out.AV.Available || out.AV.State != "faulted" || out.AV.Fault.Service != "av" || out.AV.Error == "" {
				t.Fatalf("fault API lost engine evidence: %d %s", rec.Code, rec.Body)
			}
		})
	}
}
