// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestUninspectableRuleWarningHeader(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DataPlane.NFQueueGroup = 101
	cfg.DataPlane.DPIEnabled = false
	cfg.Firewall.Rules = []config.Rule{{ID: "uninspectable", Action: config.ActionAllow, ICS: config.ICSPredicate{Protocol: "modbus", Mode: "enforce", ReadOnly: true}}}
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	if !candidateShadowWarnings(ctx, cfg) {
		t.Fatal(rec.Body.String())
	}
	if got := rec.Header().Get("X-Containd-Warnings"); !strings.Contains(got, "uninspectable") || !strings.Contains(got, "DPI is off") || !strings.Contains(got, "drops") {
		t.Fatalf("warning header=%q", got)
	}
}
