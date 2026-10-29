// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/inventory"
	"gopkg.in/yaml.v3"
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
func (e inventoryEngine) GetInventoryAssets(_ context.Context, ip string) ([]inventory.DiscoveredAsset, error) {
	return e.inv.GetAssets(ip), e.err
}
func (e inventoryEngine) ClearInventory(context.Context) error {
	if e.err == nil {
		e.inv.Clear()
	}
	return e.err
}

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
			{"list", listInventoryHandler}, {"iec104", iec104InventoryHandler}, {"clear", clearInventoryHandler}, {"get", getInventoryAssetsHandler},
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

func TestInventoryObservationsRegisteredRoute(t *testing.T) {
	const ip = "192.0.2.1"
	inv := inventory.New()
	key := flow.Key{SrcIP: net.ParseIP(ip), DstIP: net.ParseIP("192.0.2.2"), SrcPort: 50000, DstPort: 502, Proto: 6}
	inv.RecordEvent(ip, "192.0.2.2", dpi.Event{Proto: "modbus", FlowID: key.Hash()})
	key = flow.Key{SrcIP: net.ParseIP("192.0.2.3"), DstIP: net.ParseIP(ip), SrcPort: 50001, DstPort: 502, Proto: 6}.Reversed()
	inv.RecordEvent(ip, "192.0.2.3", dpi.Event{Proto: "modbus", FlowID: key.Hash()})
	inv.RecordEvent(ip, "192.0.2.2", dpi.Event{Proto: "modbus"})
	inv.RecordEvent(ip, "192.0.2.2", dpi.Event{Proto: "cip"})
	server := NewServerWithEngine(&mockStore{}, nil, inventoryEngine{inv: inv})
	w := httptest.NewRecorder()
	server.ServeHTTP(w, authedRequest("GET", "/api/v1/inventory/"+ip, nil))
	var got []inventory.DiscoveredAsset
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want := inv.GetAssets(ip)
	if w.Code != 200 || len(got) != 4 || !reflect.DeepEqual(got, want) {
		t.Fatalf("lookup: %d %+v; want %+v", w.Code, got, want)
	}
	w = httptest.NewRecorder()
	server.ServeHTTP(w, authedRequest("GET", "/api/v1/inventory", nil))
	var list []inventory.DiscoveredAsset
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || len(list) < len(got) || !reflect.DeepEqual(list[:len(got)], got) {
		t.Fatalf("list and lookup disagree: %d %+v", w.Code, list)
	}
	w = httptest.NewRecorder()
	server.ServeHTTP(w, authedRequest("GET", "/api/v1/inventory/192.0.2.99", nil))
	if w.Code != 404 || !strings.Contains(w.Body.String(), `"error"`) {
		t.Fatalf("missing lookup: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	server.ServeHTTP(w, authedRequest("DELETE", "/api/v1/inventory", nil))
	if w.Code != 200 {
		t.Fatalf("clear: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	server.ServeHTTP(w, authedRequest("GET", "/api/v1/inventory/"+ip, nil))
	if w.Code != 404 {
		t.Fatalf("lookup after clear: %d %s", w.Code, w.Body.String())
	}
}

func TestInventoryLookupOpenAPI(t *testing.T) {
	data, err := os.ReadFile("../../docs/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	type schema struct {
		Type  string `yaml:"type"`
		Items struct {
			Ref string `yaml:"$ref"`
		} `yaml:"items"`
	}
	var spec struct {
		Paths map[string]map[string]struct {
			Summary   string `yaml:"summary"`
			Responses map[string]struct {
				Content map[string]struct {
					Schema schema `yaml:"schema"`
				} `yaml:"content"`
			} `yaml:"responses"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}
	op := spec.Paths["/inventory/{ip}"]["get"]
	s := op.Responses["200"].Content["application/json"].Schema
	if op.Summary != "List discovered observations for an IP" || s.Type != "array" ||
		s.Items.Ref != "#/components/schemas/InventoryDiscoveredAsset" {
		t.Fatalf("unexpected lookup contract: %+v", op)
	}
	for _, status := range []string{"404", "503"} {
		if _, ok := op.Responses[status]; !ok {
			t.Fatalf("lookup contract missing %s", status)
		}
	}
}
