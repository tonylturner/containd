// SPDX-License-Identifier: Apache-2.0
package engineapp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
	"go.uber.org/zap"
)

func TestManagementStartupRejectsUnsafeEngineOptions(t *testing.T) {
	r := &mgmtpath.Reservation{Device: "reserved", Local: netip.MustParsePrefix("10.99.99.2/24"), Port: 8080}
	disabled := false
	for _, opts := range []Options{
		{Reservation: r, Addr: ":8081"},
		{Reservation: r, Addr: "127.0.0.1:8081", EnforceEnabled: &disabled},
	} {
		if err := Run(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "reserved management path") {
			t.Fatalf("unsafe startup accepted: %v", err)
		}
	}
}

func TestManagementPartialAPIsRejectBeforeSideEffects(t *testing.T) {
	r := &mgmtpath.Reservation{Device: "reserved", Local: netip.MustParsePrefix("10.99.99.2/24"), Port: 8080, Sources: []netip.Addr{netip.MustParseAddr("10.99.99.10")}}
	dp, err := dpengine.New(dpengine.Config{Enforce: dpengine.EnforceConfig{ClearMark: noPolicyMarks, Enabled: true, ManagementReservation: r}})
	if err != nil {
		t.Fatal(err)
	}
	logger := zap.NewNop().Sugar()
	owner := newOwnershipManager(logger)
	owner.reservation = r
	cfgHandler := configHandler(logger, dp, &simulationManager{}, testProtectionCoordinator(t, dp))
	svcHandler := servicesHandler(logger, dp, owner, nil, nil, nil, testProtectionCoordinator(t, dp))
	for _, tc := range []struct {
		name, body string
		handler    http.Handler
	}{
		{"interfaces", `[{"name":"lan3","device":"reserved","addresses":["10.99.99.8/24"]}]`, interfacesHandler(logger, owner)},
		{"interfaces_missing", `[]`, interfacesHandler(logger, owner)},
		{"routing", `{"rules":[{"priority":1,"table":201}]}`, routingHandler(logger, owner)},
		{"routing_priority_wrap", `{"rules":[{"priority":4294967296,"table":201}]}`, routingHandler(logger, owner)},
		{"routing_local_default", `{"routes":[{"dst":"0.0.0.0/0","iface":"teaching","table":255}]}`, routingHandler(logger, owner)},
		{"services", `{"vpn":{"wireguard":{"interface":"reserved","enabled":false}}}`, svcHandler},
		{"config", `{"enforcement":false}`, cfgHandler},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.handler.ServeHTTP(rec, protectionRequest(http.MethodPost, "/internal/"+tc.name+"?mode=replace", strings.NewReader(tc.body)))
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "reserved management path") {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
	for name, handler := range map[string]http.Handler{"config": cfgHandler, "services": svcHandler} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/internal/"+name, nil))
		if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "reserved") {
			t.Fatalf("rejected %s updated its state: %s", name, rec.Body.String())
		}
	}
	if len(owner.currentInterfaces()) != 0 {
		t.Fatal("rejected interface payload changed ownership")
	}
	if len(dp.Events().List(100)) != 0 {
		t.Fatal("rejected service changed event state")
	}
}
