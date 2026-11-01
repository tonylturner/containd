// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapi

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/coverage"
	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/inventory"
	"github.com/tonylturner/containd/pkg/dp/netcfg"
	"github.com/tonylturner/containd/pkg/dp/pcap"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/stats"
)

func TestNewHTTPClient(t *testing.T) {
	t.Parallel()

	c := NewHTTPClient("http://127.0.0.1:8081")
	if c.BaseURL != "http://127.0.0.1:8081" {
		t.Fatalf("BaseURL = %q", c.BaseURL)
	}
	if c.Client == nil || c.Client.Timeout != 5*time.Second {
		t.Fatalf("Client = %#v", c.Client)
	}
}

func TestEngineStatusError(t *testing.T) {
	t.Parallel()

	resp := &http.Response{
		StatusCode: http.StatusBadGateway,
		Body:       io.NopCloser(strings.NewReader("bad upstream")),
	}
	if err := engineStatusError(resp, "engine failed"); err == nil || !strings.Contains(err.Error(), "bad upstream") {
		t.Fatalf("engineStatusError = %v", err)
	}
}

func TestInventoryAssetsClient(t *testing.T) {
	want := []inventory.DiscoveredAsset{
		{IP: "192.0.2.50", Protocol: "cip", Role: "client"},
		{IP: "192.0.2.50", Protocol: "modbus", Role: ""},
		{IP: "192.0.2.50", Protocol: "modbus", Role: "master"},
		{IP: "192.0.2.50", Protocol: "modbus", Role: "slave"},
	}
	body, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, body string
		status     int
		wantErr    bool
	}{
		{"observations", string(body), 200, false},
		{"missing", "", 404, false},
		{"unavailable", `{"error":"inventory unavailable"}`, 503, true},
		{"singular rejected", `{"ip":"192.0.2.50","protocol":"modbus"}`, 200, true},
		{"null rejected", "null", 200, true},
		{"malformed rejected", "[", 200, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if _, err := io.Copy(io.Discard, r.Body); err != nil {
					t.Error(err)
					return
				}
				if r.Method != http.MethodGet || (r.URL.Path != "/internal/inventory/192.0.2.50" && r.URL.Path != "/internal/inventory") {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				// Static fixtures deliberately include malformed JSON to exercise the client decoder.
				// nosemgrep: go.lang.security.audit.xss.no-io-writestring-to-responsewriter.no-io-writestring-to-responsewriter
				_, _ = io.WriteString(w, tc.body)
			}))
			defer srv.Close()
			client := NewHTTPClient(srv.URL)
			got, err := client.GetInventoryAssets(context.Background(), " 192.0.2.50 ")
			if (err != nil) != tc.wantErr {
				t.Fatalf("GetInventoryAssets error: %v", err)
			}
			if tc.name == "observations" {
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("got %+v; want %+v", got, want)
				}
				list, err := client.ListInventory(context.Background())
				if err != nil || !reflect.DeepEqual(list, got) {
					t.Fatalf("list and lookup disagree: %+v / %v", list, err)
				}
			}
			if tc.status == 404 && got != nil {
				t.Fatalf("missing IP returned observations: %+v", got)
			}
		})
	}
}

func TestHTTPClientRepresentativeEndpoints(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mux := http.NewServeMux()
	mux.HandleFunc("/internal/apply_rules", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("apply_rules method = %s", r.Method)
		}
		var snap rules.Snapshot
		if err := json.NewDecoder(r.Body).Decode(&snap); err != nil {
			t.Fatalf("decode snapshot: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/internal/config", func(w http.ResponseWriter, r *http.Request) {
		var cfg config.DataPlaneConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			t.Fatalf("decode dataplane config: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/internal/services", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "service apply failed", http.StatusBadRequest)
	})
	mux.HandleFunc("/internal/interfaces", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("mode"); got != "replace" {
			t.Fatalf("interfaces mode = %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/internal/stats/protocols", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("null"))
	})
	mux.HandleFunc("/internal/inventory/192.0.2.50", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	mux.HandleFunc("/internal/dhcp/leases", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "dhcp unavailable", http.StatusServiceUnavailable)
	})
	mux.HandleFunc("/internal/wireguard/status", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("iface"); got != "wg0" {
			t.Fatalf("wireguard iface = %q", got)
		}
		_ = json.NewEncoder(w).Encode(netcfg.WireGuardStatus{Interface: "wg0", Present: true})
	})
	mux.HandleFunc("/internal/interfaces/state", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]config.InterfaceState{{Name: "wan", Index: 1, Up: true}})
	})
	mux.HandleFunc("/internal/events", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("limit"); got != "5" {
			t.Fatalf("events limit = %q", got)
		}
		_ = json.NewEncoder(w).Encode([]dpevents.Event{{ID: 1, Proto: "dns", Kind: "query"}})
	})
	mux.HandleFunc("/internal/pcap/config", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(config.PCAPConfig{Enabled: true})
		case http.MethodPost:
			_ = json.NewEncoder(w).Encode(config.PCAPConfig{Enabled: true})
		default:
			t.Fatalf("pcap config method = %s", r.Method)
		}
	})
	mux.HandleFunc("/internal/pcap/upload", func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Content-Type"), "multipart/form-data") {
			t.Fatalf("upload content-type = %q", r.Header.Get("Content-Type"))
		}
		file, _, err := r.FormFile("file")
		if err != nil {
			t.Fatalf("FormFile: %v", err)
		}
		defer file.Close()
		body, err := io.ReadAll(file)
		if err != nil {
			t.Fatalf("ReadAll upload: %v", err)
		}
		if string(body) != "pcap-bytes" {
			t.Fatalf("uploaded body = %q", string(body))
		}
		_ = json.NewEncoder(w).Encode(pcap.Item{Name: "capture.pcap"})
	})
	mux.HandleFunc("/internal/blocks/host", func(w http.ResponseWriter, r *http.Request) {
		var req blockHostRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode block host: %v", err)
		}
		if req.IP != "192.0.2.10" || req.TTLSeconds != 30 {
			t.Fatalf("block host req = %#v", req)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/internal/blocks/flow", func(w http.ResponseWriter, r *http.Request) {
		var req blockFlowRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode block flow: %v", err)
		}
		if req.SrcIP != "192.0.2.10" || req.DstIP != "192.0.2.20" || req.TTLSeconds != 45 {
			t.Fatalf("block flow req = %#v", req)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewHTTPClient(srv.URL)
	if err := c.ApplyRules(ctx, rules.Snapshot{}); err != nil {
		t.Fatalf("ApplyRules: %v", err)
	}
	if err := c.Configure(ctx, config.DataPlaneConfig{Enforcement: true}); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	if _, err := c.ConfigureServices(ctx, config.ServicesConfig{}); err == nil || !strings.Contains(err.Error(), "service apply failed") {
		t.Fatalf("ConfigureServices error = %v", err)
	}
	if err := c.ConfigureInterfacesReplace(ctx, []config.Interface{{Name: "wan"}}); err != nil {
		t.Fatalf("ConfigureInterfacesReplace: %v", err)
	}
	statsOut, err := c.ListProtoStats(ctx)
	if err != nil {
		t.Fatalf("ListProtoStats: %v", err)
	}
	if len(statsOut) != 0 {
		t.Fatalf("ListProtoStats = %#v, want empty slice", statsOut)
	}
	asset, err := c.GetInventoryAssets(ctx, "192.0.2.50")
	if err != nil || asset != nil {
		t.Fatalf("GetInventoryAssets = %#v, %v; want nil, nil", asset, err)
	}
	if _, err := c.ListDHCPLeases(ctx); err == nil || !strings.Contains(err.Error(), "dhcp unavailable") {
		t.Fatalf("ListDHCPLeases error = %v", err)
	}
	wg, err := c.GetWireGuardStatus(ctx, "wg0")
	if err != nil || !wg.Present || wg.Interface != "wg0" {
		t.Fatalf("GetWireGuardStatus = %#v, %v", wg, err)
	}
	ifaces, err := c.ListInterfaceState(ctx)
	if err != nil || len(ifaces) != 1 || ifaces[0].Name != "wan" || !ifaces[0].Up {
		t.Fatalf("ListInterfaceState = %#v, %v", ifaces, err)
	}
	events, err := c.ListEvents(ctx, 5)
	if err != nil || len(events) != 1 || events[0].ID != 1 {
		t.Fatalf("ListEvents = %#v, %v", events, err)
	}
	pcapCfg, err := c.PcapConfig(ctx)
	if err != nil || !pcapCfg.Enabled {
		t.Fatalf("PcapConfig = %#v, %v", pcapCfg, err)
	}
	pcapCfg, err = c.SetPcapConfig(ctx, config.PCAPConfig{Enabled: true})
	if err != nil || !pcapCfg.Enabled {
		t.Fatalf("SetPcapConfig = %#v, %v", pcapCfg, err)
	}
	item, err := c.UploadPcap(ctx, "capture.pcap", strings.NewReader("pcap-bytes"))
	if err != nil || item.Name != "capture.pcap" {
		t.Fatalf("UploadPcap = %#v, %v", item, err)
	}
	if err := c.BlockHostTemp(ctx, net.ParseIP("192.0.2.10"), 30*time.Second); err != nil {
		t.Fatalf("BlockHostTemp: %v", err)
	}
	if err := c.BlockFlowTemp(ctx, net.ParseIP("192.0.2.10"), net.ParseIP("192.0.2.20"), "tcp", "502", 45*time.Second); err != nil {
		t.Fatalf("BlockFlowTemp: %v", err)
	}
}

func TestHTTPClientEmptyBaseURLGuards(t *testing.T) {
	t.Parallel()

	c := &HTTPClient{}
	ctx := context.Background()
	if err := c.ApplyRules(ctx, rules.Snapshot{}); err == nil {
		t.Fatal("expected ApplyRules to reject empty BaseURL")
	}
	if _, err := c.PcapConfig(ctx); err == nil {
		t.Fatal("expected PcapConfig to reject empty BaseURL")
	}
	if err := c.BlockHostTemp(ctx, nil, 0); err == nil {
		t.Fatal("expected BlockHostTemp to reject nil ip")
	}
	if err := c.BlockFlowTemp(ctx, nil, net.ParseIP("192.0.2.20"), "tcp", "443", 0); err == nil {
		t.Fatal("expected BlockFlowTemp to reject nil src ip")
	}
}

func TestHTTPClientAdditionalEndpoints(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	mux := http.NewServeMux()
	mux.HandleFunc("/internal/interfaces", func(w http.ResponseWriter, r *http.Request) {
		var ifaces []config.Interface
		if err := json.NewDecoder(r.Body).Decode(&ifaces); err != nil {
			t.Fatalf("decode interfaces: %v", err)
		}
		if got := r.URL.Query().Get("mode"); got != "" {
			t.Fatalf("unexpected interfaces mode = %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/internal/routing", func(w http.ResponseWriter, r *http.Request) {
		var routing config.RoutingConfig
		if err := json.NewDecoder(r.Body).Decode(&routing); err != nil {
			t.Fatalf("decode routing: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/internal/stats/top-talkers", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("n"); got != "3" {
			t.Fatalf("top-talkers n = %q", got)
		}
		_ = json.NewEncoder(w).Encode([]stats.FlowStats{{SrcIP: "192.0.2.10", DstIP: "192.0.2.20", Protocol: "dns", Packets: 4, Bytes: 256}})
	})
	mux.HandleFunc("/internal/inventory", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode([]inventory.DiscoveredAsset{{IP: "192.0.2.50", Protocol: "modbus", Role: "slave"}})
		case http.MethodDelete:
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("inventory method = %s", r.Method)
		}
	})
	mux.HandleFunc("/internal/conntrack", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if got := r.URL.Query().Get("limit"); got != "2" {
				t.Fatalf("conntrack limit = %q", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"entries": []dpengine.TaggedConnection{{Entry: conntrack.Entry{Proto: "tcp", State: "ESTABLISHED", Src: "192.0.2.10", Dst: "192.0.2.20"}, Tags: []string{"plc"}}},
			})
		case http.MethodPost:
			var req conntrack.KillRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode conntrack delete: %v", err)
			}
			if err := req.Validate(); err != nil {
				t.Errorf("invalid kill request: %v", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			until := time.Now().Add(time.Minute)
			_ = json.NewEncoder(w).Encode(conntrack.KillResult{Scope: req.Scope, Matched: 1, Deleted: 1, ConntrackDeleted: true, RevocationInstalled: true, BlockedUntil: &until, Closure: "TCP reset signalled on next packet"})
		default:
			t.Fatalf("conntrack method = %s", r.Method)
		}
	})
	mux.HandleFunc("/internal/flows", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("limit"); got != "4" {
			t.Fatalf("flows limit = %q", got)
		}
		_ = json.NewEncoder(w).Encode([]dpevents.FlowSummary{{FlowID: "flow-1", SrcIP: "192.0.2.10", DstIP: "192.0.2.20", EventCount: 3}})
	})
	mux.HandleFunc("/internal/simulation", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(SimulationStatus{Running: false})
		case http.MethodPost:
			var req map[string]string
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode simulation control: %v", err)
			}
			_ = json.NewEncoder(w).Encode(SimulationStatus{Running: req["action"] == "start"})
		default:
			t.Fatalf("simulation method = %s", r.Method)
		}
	})
	mux.HandleFunc("/internal/pcap/start", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(pcap.Status{Running: true, Interfaces: []string{"eth0"}})
	})
	mux.HandleFunc("/internal/pcap/stop", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(pcap.Status{Running: false})
	})
	mux.HandleFunc("/internal/pcap/status", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(pcap.Status{Running: true, Interfaces: []string{"eth0"}})
	})
	mux.HandleFunc("/internal/pcap/list", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]pcap.Item{{Name: "capture-1.pcap", Interface: "eth0"}})
	})
	mux.HandleFunc("/internal/pcap/delete", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("name"); got != "capture-1.pcap" {
			t.Fatalf("delete pcap name = %q", got)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/internal/pcap/tag", func(w http.ResponseWriter, r *http.Request) {
		var req pcap.TagRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode pcap tag: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/internal/pcap/replay", func(w http.ResponseWriter, r *http.Request) {
		var req pcap.ReplayRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode pcap replay: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/internal/pcap/download", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("name"); got != "capture-1.pcap" {
			t.Fatalf("download pcap name = %q", got)
		}
		_, _ = w.Write([]byte("pcap-download"))
	})
	mux.HandleFunc("/internal/pcap/analyze", func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Content-Type"), "multipart/form-data") {
			t.Fatalf("analyze content-type = %q", r.Header.Get("Content-Type"))
		}
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			t.Error(err)
			return
		}
		_ = json.NewEncoder(w).Encode(pcap.ImportResult{Stats: pcap.AnalysisResult{PacketCount: 1, Protocols: map[string]int{"dns": 1}}})
	})
	mux.HandleFunc("/internal/pcap/analyze/capture-1.pcap", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(pcap.ImportResult{Stats: pcap.AnalysisResult{PacketCount: 2, Protocols: map[string]int{"modbus": 1}}})
	})
	mux.HandleFunc("/internal/ruleset_status", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(dpengine.RulesetStatus{Ruleset: "loaded", ICSCoverage: []coverage.Rule{
			{RuleID: "read", Protocol: "modbus", Mode: "enforce", State: coverage.Partial,
				Reasons: []coverage.Reason{{Code: coverage.ExclusionOverlap, Message: "excluded", Value: "10.0.0.2", Matches: 3}}}}})
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewHTTPClient(srv.URL)
	if err := c.ConfigureInterfaces(ctx, []config.Interface{{Name: "wan", Device: "eth0"}}); err != nil {
		t.Fatalf("ConfigureInterfaces: %v", err)
	}
	if err := c.ConfigureRouting(ctx, config.RoutingConfig{}); err != nil {
		t.Fatalf("ConfigureRouting: %v", err)
	}
	if err := c.ConfigureRoutingReplace(ctx, config.RoutingConfig{}); err != nil {
		t.Fatalf("ConfigureRoutingReplace: %v", err)
	}
	talkers, err := c.ListTopTalkers(ctx, 3)
	if err != nil || len(talkers) != 1 || talkers[0].Protocol != "dns" {
		t.Fatalf("ListTopTalkers = %#v, %v", talkers, err)
	}
	inv, err := c.ListInventory(ctx)
	if err != nil || len(inv) != 1 || inv[0].IP != "192.0.2.50" {
		t.Fatalf("ListInventory = %#v, %v", inv, err)
	}
	if err := c.ClearInventory(ctx); err != nil {
		t.Fatalf("ClearInventory: %v", err)
	}
	entries, err := c.ListConntrack(ctx, 2)
	if err != nil || len(entries) != 1 || entries[0].State != "ESTABLISHED" || len(entries[0].Tags) != 1 || entries[0].Tags[0] != "plc" {
		t.Fatalf("ListConntrack = %#v, %v", entries, err)
	}
	if result, err := c.DeleteConntrack(ctx, conntrack.KillRequest{DeleteRequest: conntrack.DeleteRequest{Proto: "tcp", Src: "192.0.2.10", Dst: "192.0.2.20", Sport: 1234, Dport: 443}}); err != nil || !result.RevocationInstalled {
		t.Fatalf("DeleteConntrack: %v", err)
	}
	flows, err := c.ListFlows(ctx, 4)
	if err != nil || len(flows) != 1 || flows[0].FlowID != "flow-1" {
		t.Fatalf("ListFlows = %#v, %v", flows, err)
	}
	sim, err := c.SimulationStatus(ctx)
	if err != nil || sim.Running {
		t.Fatalf("SimulationStatus = %#v, %v", sim, err)
	}
	sim, err = c.SimulationControl(ctx, "start")
	if err != nil || !sim.Running {
		t.Fatalf("SimulationControl = %#v, %v", sim, err)
	}
	startStatus, err := c.StartPcap(ctx, config.PCAPConfig{Enabled: true})
	if err != nil || !startStatus.Running {
		t.Fatalf("StartPcap = %#v, %v", startStatus, err)
	}
	stopStatus, err := c.StopPcap(ctx)
	if err != nil || stopStatus.Running {
		t.Fatalf("StopPcap = %#v, %v", stopStatus, err)
	}
	status, err := c.PcapStatus(ctx)
	if err != nil || !status.Running {
		t.Fatalf("PcapStatus = %#v, %v", status, err)
	}
	items, err := c.ListPcaps(ctx)
	if err != nil || len(items) != 1 || items[0].Name != "capture-1.pcap" {
		t.Fatalf("ListPcaps = %#v, %v", items, err)
	}
	if err := c.DeletePcap(ctx, "capture-1.pcap"); err != nil {
		t.Fatalf("DeletePcap: %v", err)
	}
	if err := c.TagPcap(ctx, pcap.TagRequest{Name: "capture-1.pcap", Tags: []string{"lab"}}); err != nil {
		t.Fatalf("TagPcap: %v", err)
	}
	if err := c.ReplayPcap(ctx, pcap.ReplayRequest{Name: "capture-1.pcap", Interface: "eth0", RatePPS: 100}); err != nil {
		t.Fatalf("ReplayPcap: %v", err)
	}
	resp, err := c.DownloadPcap(ctx, "capture-1.pcap")
	if err != nil {
		t.Fatalf("DownloadPcap: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(body) != "pcap-download" {
		t.Fatalf("DownloadPcap body = %q, %v", string(body), err)
	}
	analysis, err := c.AnalyzePcap(ctx, "capture-1.pcap", strings.NewReader("pcap-bytes"))
	if err != nil || analysis.Stats.PacketCount != 1 || analysis.Stats.Protocols["dns"] != 1 {
		t.Fatalf("AnalyzePcap = %#v, %v", analysis, err)
	}
	analysis, err = c.AnalyzePcapByName(ctx, "capture-1.pcap")
	if err != nil || analysis.Stats.PacketCount != 2 || analysis.Stats.Protocols["modbus"] != 1 {
		t.Fatalf("AnalyzePcapByName = %#v, %v", analysis, err)
	}
	ruleset, err := c.RulesetStatus(ctx)
	if err != nil || ruleset.Ruleset != "loaded" || len(ruleset.ICSCoverage) != 1 || ruleset.ICSCoverage[0].Reasons[0].Matches != 3 {
		t.Fatalf("RulesetStatus = %#v, %v", ruleset, err)
	}
}

func TestRuntimeHealthReadsEngineHealth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok","component":"engine","bootId":"engine-boot-1","iec104Enforcement":{"active":true,"healthy":false,"reason":"queue down"},"ipv4Forwarding":"disabled"}`))
	}))
	defer srv.Close()
	client := NewHTTPClient(srv.URL)
	health, err := client.RuntimeHealth(context.Background())
	if err != nil ||
		health.BootID != "engine-boot-1" ||
		health.IEC104Enforcement != (dpengine.IEC104Enforcement{Active: true, Reason: "queue down"}) ||
		health.IPv4Forwarding != netcfg.IPv4ForwardingDisabled {
		t.Fatalf("RuntimeHealth = %+v, %v", health, err)
	}
	old := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer old.Close()
	if _, err := NewHTTPClient(old.URL).RuntimeHealth(context.Background()); err == nil {
		t.Fatal("an engine without iec104Enforcement must not read as healthy")
	}
}

func TestRuntimeHealthWithoutBootID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok","iec104Enforcement":{"active":false,"healthy":true,"reason":""}}`))
	}))
	defer srv.Close()
	health, err := NewHTTPClient(srv.URL).RuntimeHealth(context.Background())
	if err != nil || health.BootID != "" {
		t.Fatalf("legacy RuntimeHealth = %+v, %v", health, err)
	}
}

// TestConfigureServicesWarnings: a services apply the engine accepted with
// warnings returns them; a failed one is an error carrying the engine's
// detail.
func TestConfigureServicesWarnings(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		status   int
		body     string
		warnings []string
		errText  string
		service  string
	}{
		{"applied", http.StatusOK, `{"faults":[]}`, nil, "", ""},
		{"pending", http.StatusOK, `{"faults":[],"warnings":["AV backend is still starting: clamd not ready; scanning is pending until it is ready"]}`,
			[]string{"AV backend is still starting: clamd not ready; scanning is pending until it is ready"}, "", ""},
		{"runtime", http.StatusOK, `{"faults":[{"service":"dhcp","kind":"runtime","message":"runtime apply failed"}]}`, nil, "", "dhcp"},
		{"no body", http.StatusNoContent, "", nil, "engine services response", ""},
		{"missing faults", http.StatusOK, `{"status":"applied"}`, nil, "missing faults", ""},
		{"invalid service", http.StatusOK, `{"faults":[{"service":"dns","kind":"runtime","message":"failed"}]}`, nil, "invalid runtime fault", ""},
		{"invalid kind", http.StatusOK, `{"faults":[{"service":"av","kind":"config","message":"failed"}]}`, nil, "invalid runtime fault", ""},
		{"duplicate", http.StatusOK, `{"faults":[{"service":"av","kind":"runtime","message":"failed"},{"service":"av","kind":"runtime","message":"failed"}]}`, nil, "invalid runtime fault", ""},
		{"malformed", http.StatusOK, `{"status":`, nil, "engine services response", ""},
		{"unavailable", http.StatusServiceUnavailable, "request refused", nil, "engine services status 503: request refused", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/internal/services" || r.Method != http.MethodPost {
					t.Errorf("%s %s", r.Method, r.URL.Path)
				}
				var svc config.ServicesConfig
				if err := json.NewDecoder(r.Body).Decode(&svc); err != nil {
					t.Errorf("decode services: %v", err)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				// Static fixtures deliberately include malformed JSON to exercise the client decoder.
				// nosemgrep: go.lang.security.audit.xss.no-io-writestring-to-responsewriter.no-io-writestring-to-responsewriter
				_, _ = io.WriteString(w, tc.body)
			}))
			defer srv.Close()
			result, err := NewHTTPClient(srv.URL).ConfigureServices(context.Background(), config.ServicesConfig{})
			if tc.errText != "" {
				if err == nil || !strings.Contains(err.Error(), tc.errText) || result.Faults != nil {
					t.Fatalf("result=%v err=%v, want error %q", result, err, tc.errText)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(result.Warnings, tc.warnings) {
				t.Fatalf("result=%v err=%v, want %v", result, err, tc.warnings)
			}
			if tc.service != "" && (len(result.Faults) != 1 || result.Faults[0].Service != tc.service || result.Faults[0].Kind != "runtime") {
				t.Fatalf("lost typed runtime fault: %+v", result)
			}
		})
	}
}
