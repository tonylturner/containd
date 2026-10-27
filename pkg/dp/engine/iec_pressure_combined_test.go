// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	httpapi "github.com/tonylturner/containd/api/http"
	"github.com/tonylturner/containd/pkg/common/metrics"
	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/session"
)

func TestIECPressureCombinedRegistry(t *testing.T) {
	// Combined mode constructs both planes in one process. Rebuilding either
	// must not register collectors again, and both handlers use the same registry.
	for i := 0; i < 2; i++ {
		dp, err := engine.New(engine.Config{ResetInjector: &session.Fake{}})
		if err != nil {
			t.Fatal(err)
		}
		metrics.SetIEC104PressureReader(dp.IEC104PressureMetrics)
		for name, handler := range map[string]http.Handler{
			"management": httpapi.NewServer(nil, nil),
			"engine":     promhttp.Handler(),
		} {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
			if w.Code != http.StatusOK {
				t.Fatalf("%s: status %d", name, w.Code)
			}
			if !strings.Contains(w.Body.String(), "containd_dp_iec104_sessions_limit 4096\n") {
				t.Fatalf("%s: live IEC104 metrics missing", name)
			}
		}
	}
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, family := range families {
		if family.GetName() == "containd_dp_iec104_sessions_limit" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected one shared IEC104 metric family, got %d", count)
	}
}
