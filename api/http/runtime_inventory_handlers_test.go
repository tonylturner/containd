// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpapi

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/dp/inventory"
)

type inventoryEngine struct {
	EngineClient
	inv *inventory.Inventory
	err error
}

func (e inventoryEngine) ListInventory(context.Context) ([]inventory.DiscoveredAsset, error) {
	return e.inv.List(), e.err
}
func (e inventoryEngine) IEC104Inventory(context.Context) (inventory.IEC104Snapshot, error) {
	return e.inv.SnapshotIEC104(), e.err
}
func (e inventoryEngine) GetInventoryAsset(context.Context, string) (*inventory.DiscoveredAsset, error) {
	return nil, e.err
}
func (e inventoryEngine) ClearInventory(context.Context) error { return e.err }

func TestInventoryAvailability(t *testing.T) {
	for _, tc := range []struct {
		name   string
		engine EngineClient
		status int
	}{
		{"missing", nil, 503}, {"unsupported", &mockEngine{}, 503},
		{"unreachable", inventoryEngine{inv: inventory.New(), err: errors.New("offline")}, 503},
		{"live", inventoryEngine{inv: inventory.New()}, 200},
	} {
		for _, route := range []struct {
			name string
			h    func(EngineClient) gin.HandlerFunc
		}{
			{"list", listInventoryHandler}, {"iec104", iec104InventoryHandler}, {"clear", clearInventoryHandler}, {"get", getInventoryAssetHandler},
		} {
			t.Run(tc.name+"/"+route.name, func(t *testing.T) {
				w := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(w)
				c.Request = httptest.NewRequest("GET", "/inventory", nil)
				route.h(tc.engine)(c)
				want := tc.status
				if tc.name == "live" && route.name == "get" {
					want = 404
				}
				if w.Code != want {
					t.Fatalf("%d %s", w.Code, w.Body.String())
				}
				if want == 503 && (!strings.Contains(w.Body.String(), `"error"`) || !strings.Contains(w.Header().Get("Content-Type"), "application/json")) {
					t.Fatal(w.Body.String())
				}
			})
		}
	}
}

func TestIEC104InventoryRegisteredRoute(t *testing.T) {
	server := NewServerWithEngine(&mockStore{cfg: nil}, nil, inventoryEngine{inv: inventory.New()})
	w := httptest.NewRecorder()
	server.ServeHTTP(w, authedRequest("GET", "/api/v1/inventory/iec104", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"pointsPerCA":256`) {
		t.Fatal(w.Code, w.Body.String())
	}
}
