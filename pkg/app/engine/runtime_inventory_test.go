// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engineapp

import (
	"encoding/json"
	"net"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/inventory"
)

func TestInventoryObservationsForIP(t *testing.T) {
	e, err := engine.New(engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	const ip = "192.0.2.1"
	inv := e.Inventory()
	key := flow.Key{SrcIP: net.ParseIP(ip), DstIP: net.ParseIP("192.0.2.2"), SrcPort: 50000, DstPort: 502, Proto: 6}
	inv.RecordEvent(ip, "192.0.2.2", dpi.Event{Proto: "modbus", FlowID: key.Hash()})
	key = flow.Key{SrcIP: net.ParseIP("192.0.2.3"), DstIP: net.ParseIP(ip), SrcPort: 50001, DstPort: 502, Proto: 6}.Reversed()
	inv.RecordEvent(ip, "192.0.2.3", dpi.Event{Proto: "modbus", FlowID: key.Hash()})
	inv.RecordEvent(ip, "192.0.2.2", dpi.Event{Proto: "modbus"})
	inv.RecordEvent(ip, "192.0.2.2", dpi.Event{Proto: "cip"})

	w := httptest.NewRecorder()
	inventoryItemHandler(e)(w, httptest.NewRequest("GET", "/internal/inventory/"+ip, nil))
	var got []inventory.DiscoveredAsset
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want := inv.GetAssets(ip)
	if w.Code != 200 || len(got) != 4 || !reflect.DeepEqual(got, want) {
		t.Fatalf("lookup: %d %+v; want %+v", w.Code, got, want)
	}
	w = httptest.NewRecorder()
	inventoryHandler(e)(w, httptest.NewRequest("GET", "/internal/inventory", nil))
	var list []inventory.DiscoveredAsset
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || len(list) < len(want) || !reflect.DeepEqual(list[:len(want)], want) {
		t.Fatalf("list and lookup disagree: %d %+v", w.Code, list)
	}
	for _, tc := range []struct {
		method, suffix string
		status         int
	}{
		{"GET", "192.0.2.99", 404}, {"GET", "", 400}, {"POST", ip, 405},
	} {
		w := httptest.NewRecorder()
		inventoryItemHandler(e)(w, httptest.NewRequest(tc.method, "/internal/inventory/"+tc.suffix, nil))
		if w.Code != tc.status {
			t.Fatalf("%s %q: %d %s", tc.method, tc.suffix, w.Code, w.Body.String())
		}
	}
	inv.Clear()
	w = httptest.NewRecorder()
	inventoryItemHandler(e)(w, httptest.NewRequest("GET", "/internal/inventory/"+ip, nil))
	if w.Code != 404 {
		t.Fatalf("lookup after clear: %d %s", w.Code, w.Body.String())
	}
}

func TestInventoryIEC104Section(t *testing.T) {
	e, err := engine.New(engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	inventoryHandler(e)(w, httptest.NewRequest("GET", "/internal/inventory?section=iec104", nil))
	var s inventory.IEC104Snapshot
	if err := json.Unmarshal(w.Body.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || s.Pairs == nil || s.Limits.PointsPerCA != inventory.MaxIEC104Points {
		t.Fatal(w.Code, s)
	}
}

func TestInventoryUnavailableJSON(t *testing.T) {
	for _, tc := range []struct {
		path, method string
		item         bool
	}{
		{"/internal/inventory", "GET", false}, {"/internal/inventory?section=iec104", "GET", false},
		{"/internal/inventory", "DELETE", false}, {"/internal/inventory/192.0.2.1", "GET", true},
	} {
		w := httptest.NewRecorder()
		handler := inventoryHandler(nil)
		if tc.item {
			handler = inventoryItemHandler(nil)
		}
		handler(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != 503 || w.Header().Get("Content-Type") != "application/json" || w.Body.String() != "{\"error\":\"inventory unavailable\"}\n" {
			t.Fatal(w.Code, w.Body.String())
		}
	}
}
