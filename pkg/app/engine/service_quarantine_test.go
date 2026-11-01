// SPDX-License-Identifier: Apache-2.0
package engineapp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	"go.uber.org/zap"
)

type quarantineAVApplier struct{ cfg config.AVConfig }

func (a *quarantineAVApplier) Apply(_ context.Context, cfg config.AVConfig) error {
	a.cfg = cfg
	return nil
}

func TestServiceQuarantineDisablesBackendNotPolicy(t *testing.T) {
	av := &quarantineAVApplier{}
	gate := &gateManager{}
	body := `{"av":{"enabled":true,"backendDisabled":true,"failPolicy":"closed","httpDownload":true,"scan":{"include":[{"destPorts":["80"]}]}}}`
	rec := httptest.NewRecorder()
	servicesHandler(zap.NewNop().Sugar(), nil, nil, nil, av, gate, testProtectionCoordinator(t, newCountingDP(t))).ServeHTTP(rec,
		protectionRequest(http.MethodPost, "/internal/services", strings.NewReader(body)))
	// Independent WireGuard faults must not prevent either AV operation.
	if av.cfg.Enabled || !av.cfg.BackendDisabled || av.cfg.FailPolicy != "closed" {
		t.Fatalf("scanner backend was not stopped: %+v", av.cfg)
	}
	if !gate.av.Enabled || !gate.av.ScanGateEnabled() || gate.settings.FailPolicy != "closed" || !gate.settings.ScanDownloads {
		t.Fatalf("quarantine changed scan policy: %+v", gate.settings)
	}
}
