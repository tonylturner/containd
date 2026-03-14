// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapp

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/pcap"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func minimalPCAP() []byte {
	return []byte{
		0xd4, 0xc3, 0xb2, 0xa1,
		0x02, 0x00, 0x04, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0xff, 0xff, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00,
	}
}

func TestEngineHTTPHelpersAndHandlers(t *testing.T) {
	t.Parallel()

	dp, err := dpengine.New(dpengine.Config{})
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	now := time.Now().UTC()
	dp.Events().Append(dpevents.Event{
		Proto:     "dns",
		Kind:      "query",
		Timestamp: now,
		FlowID:    "flow-1",
		SrcIP:     "192.0.2.10",
		DstIP:     "192.0.2.20",
		DstPort:   53,
		Transport: "udp",
	})
	dp.Inventory().RecordEvent("192.0.2.10", "192.0.2.20", dpi.Event{
		Proto:      "modbus",
		Timestamp:  now,
		Attributes: map[string]any{"unit_id": uint8(1), "function_code": uint8(3)},
	})

	t.Run("health", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		healthHandler(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		var out healthResponse
		if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
			t.Fatalf("decode health: %v", err)
		}
		if out.Status != "ok" || out.Component != "engine" {
			t.Fatalf("unexpected health response: %#v", out)
		}
	})

	t.Run("events and flows", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/internal/events?limit=5", nil)
		eventsHandler(dp).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("events status = %d", rec.Code)
		}
		var events []dpevents.Event
		if err := json.NewDecoder(rec.Body).Decode(&events); err != nil {
			t.Fatalf("decode events: %v", err)
		}
		if len(events) == 0 || events[0].Proto != "dns" {
			t.Fatalf("unexpected events: %#v", events)
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, "/internal/flows?limit=5", nil)
		flowsHandler(dp).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("flows status = %d", rec.Code)
		}
		var flows []dpevents.FlowSummary
		if err := json.NewDecoder(rec.Body).Decode(&flows); err != nil {
			t.Fatalf("decode flows: %v", err)
		}
		if len(flows) == 0 {
			t.Fatal("expected at least one flow summary")
		}
	})

	t.Run("proto stats normalize nil", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/internal/stats/protocols", nil)
		protoStatsHandler(dp).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		var out []map[string]any
		if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
			t.Fatalf("decode proto stats: %v", err)
		}
		if out == nil {
			t.Fatal("expected empty slice JSON, not null")
		}
	})

	t.Run("top talkers", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/internal/stats/top-talkers?n=5", nil)
		topTalkersHandler(dp).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("top talkers status = %d", rec.Code)
		}
		var out []map[string]any
		if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
			t.Fatalf("decode top talkers: %v", err)
		}
		if out == nil {
			t.Fatal("expected [] JSON, not null")
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/internal/stats/top-talkers", nil)
		topTalkersHandler(dp).ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("top talkers method status = %d", rec.Code)
		}
	})

	t.Run("inventory list get and clear", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/internal/inventory", nil)
		inventoryHandler(dp).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("list status = %d", rec.Code)
		}
		var list []map[string]any
		if err := json.NewDecoder(rec.Body).Decode(&list); err != nil {
			t.Fatalf("decode inventory list: %v", err)
		}
		if len(list) == 0 {
			t.Fatal("expected discovered inventory assets")
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, "/internal/inventory/192.0.2.10", nil)
		inventoryItemHandler(dp).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("get status = %d", rec.Code)
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodDelete, "/internal/inventory", nil)
		inventoryHandler(dp).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("clear status = %d", rec.Code)
		}
		if assets := dp.Inventory().List(); len(assets) != 0 {
			t.Fatalf("expected cleared inventory, got %#v", assets)
		}
	})

	t.Run("interface state and ownership", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/internal/interfaces/state", nil)
		interfacesStateHandler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("interfaces state status = %d", rec.Code)
		}
		var states []map[string]any
		if err := json.NewDecoder(rec.Body).Decode(&states); err != nil {
			t.Fatalf("decode interface state: %v", err)
		}
		if len(states) == 0 {
			t.Fatal("expected at least one interface state")
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, "/internal/ownership", nil)
		ownershipHandler(newOwnershipManager(zap.NewNop().Sugar())).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("ownership status = %d", rec.Code)
		}
		var status map[string]any
		if err := json.NewDecoder(rec.Body).Decode(&status); err != nil {
			t.Fatalf("decode ownership status: %v", err)
		}
		enabled, ok := status["enabled"].(bool)
		if !ok {
			t.Fatalf("ownership status missing enabled flag: %#v", status)
		}
		if runtime.GOOS == "linux" {
			if !enabled {
				t.Fatalf("ownership status = %#v", status)
			}
		} else if enabled {
			t.Fatalf("ownership status = %#v", status)
		}
	})
}

func TestEngineParseHelpers(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/internal/events?limit=17", nil)
	if got := parseLimit(req, 5); got != 17 {
		t.Fatalf("parseLimit = %d", got)
	}
	req = httptest.NewRequest(http.MethodGet, "/internal/events?limit=bad", nil)
	if got := parseLimit(req, 5); got != 5 {
		t.Fatalf("parseLimit fallback = %d", got)
	}
	if got := firstNonEmpty("  ", "fallback"); got != "fallback" {
		t.Fatalf("firstNonEmpty blank = %q", got)
	}
	if got := firstNonEmpty("value", "fallback"); got != "value" {
		t.Fatalf("firstNonEmpty value = %q", got)
	}
}

func TestEngineAuxiliaryHandlers(t *testing.T) {
	t.Parallel()

	dp, err := dpengine.New(dpengine.Config{})
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}

	t.Run("rules handlers", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/internal/rules", nil)
		getRulesHandler(dp).ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected 404 when no rules are loaded, got %d", rec.Code)
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/internal/apply_rules", bytes.NewBufferString(`{"firewall":[],"nat":{"snat":[],"dnat":[]},"ids":{"enabled":false,"rules":null}}`))
		applyRulesHandler(dp).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("apply_rules status = %d body=%s", rec.Code, rec.Body.String())
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, "/internal/rules", nil)
		getRulesHandler(dp).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("get rules status = %d", rec.Code)
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, "/internal/ruleset_status", nil)
		rulesetStatusHandler(dp).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("ruleset status = %d", rec.Code)
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/internal/apply_rules", bytes.NewBufferString("{"))
		applyRulesHandler(dp).ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected invalid JSON status, got %d", rec.Code)
		}

		dp.LoadRules(rules.Snapshot{})
	})

	t.Run("config and simulation handlers", func(t *testing.T) {
		logger := zap.NewNop().Sugar()
		sim := &simulationManager{dpEngine: dp, logger: logger}

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/internal/config", nil)
		configHandler(logger, dp, sim).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("config GET status = %d", rec.Code)
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/internal/config", bytes.NewBufferString("{"))
		configHandler(logger, dp, sim).ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("config invalid JSON status = %d", rec.Code)
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, "/internal/simulation", nil)
		simulationHandler(sim).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"running":false`) {
			t.Fatalf("simulation GET unexpected response: %d %s", rec.Code, rec.Body.String())
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/internal/simulation", bytes.NewBufferString(`{"action":"start"}`))
		simulationHandler(sim).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || !sim.running {
			t.Fatalf("simulation start failed: %d %s", rec.Code, rec.Body.String())
		}
		sim.stop()

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/internal/simulation", bytes.NewBufferString(`{"action":"pause"}`))
		simulationHandler(sim).ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("simulation invalid action status = %d", rec.Code)
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/internal/config", bytes.NewBufferString(`{"enforcement":false,"dpiMock":true,"dpiEnabled":true,"dpiMode":"learn","captureInterfaces":["wan"],"dpiProtocols":{"dns":true}}`))
		configHandler(logger, dp, sim).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("config valid POST status = %d body=%s", rec.Code, rec.Body.String())
		}
		if !sim.running {
			t.Fatal("expected simulation manager running after dpiMock config")
		}
		sim.stop()
	})

	t.Run("block handlers unavailable and validation", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/internal/blocks/host", bytes.NewBufferString(`{"ip":"198.51.100.2","ttlSeconds":10}`))
		blockHostHandler(dp).ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("block host unavailable status = %d", rec.Code)
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/internal/blocks/flow", bytes.NewBufferString(`{"srcIp":"bad","dstIp":"198.51.100.2","proto":"tcp","dstPort":"80"}`))
		blockFlowHandler(nil).ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("block flow unavailable status = %d", rec.Code)
		}
	})

	t.Run("services and dhcp leases", func(t *testing.T) {
		logger := zap.NewNop().Sugar()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/internal/services", nil)
		servicesHandler(logger, dp, nil, nil).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("services GET status = %d", rec.Code)
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/internal/services", bytes.NewBufferString("{"))
		servicesHandler(logger, dp, nil, nil).ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("services invalid JSON status = %d", rec.Code)
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/internal/services", bytes.NewBufferString(`{"vpn":{"wireguard":{"enabled":false}}}`))
		servicesHandler(logger, dp, nil, nil).ServeHTTP(rec, req)
		if runtime.GOOS == "linux" {
			if rec.Code != http.StatusOK {
				t.Fatalf("services valid POST status = %d body=%s", rec.Code, rec.Body.String())
			}
		} else if rec.Code != http.StatusBadRequest || !strings.Contains(strings.ToLower(rec.Body.String()), "wireguard") {
			t.Fatalf("services non-linux wireguard fallback = %d body=%s", rec.Code, rec.Body.String())
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPatch, "/internal/services", nil)
		servicesHandler(logger, dp, nil, nil).ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("services method status = %d", rec.Code)
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, "/internal/dhcp/leases", nil)
		dhcpLeasesHandler(nil).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"enabled":false`) {
			t.Fatalf("dhcp leases nil response: %d %s", rec.Code, rec.Body.String())
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/internal/dhcp/leases", nil)
		dhcpLeasesHandler(nil).ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("dhcp leases method status = %d", rec.Code)
		}
	})
}

func TestEnginePcapHandlers(t *testing.T) {
	t.Parallel()

	mgr := pcap.NewManager(t.TempDir())

	t.Run("config and status", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/internal/pcap/config", nil)
		pcapConfigHandler(mgr, nil).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("pcap config GET = %d", rec.Code)
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/internal/pcap/config", bytes.NewBufferString(`{"enabled":true,"interfaces":["wan"],"snaplen":128}`))
		pcapConfigHandler(mgr, nil).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("pcap config POST = %d body=%s", rec.Code, rec.Body.String())
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, "/internal/pcap/status", nil)
		pcapStatusHandler(mgr).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("pcap status GET = %d", rec.Code)
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/internal/pcap/start", bytes.NewBufferString(`{"enabled":true,"interfaces":["wan"]}`))
		pcapStartHandler(mgr, nil).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("pcap start POST = %d body=%s", rec.Code, rec.Body.String())
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/internal/pcap/stop", nil)
		pcapStopHandler(mgr).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("pcap stop POST = %d", rec.Code)
		}
	})

	t.Run("upload list tag download delete", func(t *testing.T) {
		var body bytes.Buffer
		writer := multipart.NewWriter(&body)
		part, err := writer.CreateFormFile("file", "capture.pcap")
		if err != nil {
			t.Fatalf("CreateFormFile: %v", err)
		}
		_, _ = part.Write([]byte{0xd4, 0xc3, 0xb2, 0xa1, 0, 0, 0, 0})
		if err := writer.Close(); err != nil {
			t.Fatalf("writer.Close: %v", err)
		}

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/internal/pcap/upload", &body)
		req.Header.Set("Content-Type", writer.FormDataContentType())
		pcapUploadHandler(mgr).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("pcap upload POST = %d body=%s", rec.Code, rec.Body.String())
		}
		var item pcap.Item
		if err := json.NewDecoder(rec.Body).Decode(&item); err != nil {
			t.Fatalf("decode uploaded item: %v", err)
		}
		if item.Name == "" {
			t.Fatal("expected uploaded item name")
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, "/internal/pcap/list", nil)
		pcapListHandler(mgr).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), item.Name) {
			t.Fatalf("pcap list GET = %d body=%s", rec.Code, rec.Body.String())
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/internal/pcap/tag", bytes.NewBufferString(`{"name":"`+item.Name+`","tags":["lab","dpi"]}`))
		pcapTagHandler(mgr).ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("pcap tag POST = %d", rec.Code)
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodGet, "/internal/pcap/download?name="+item.Name, nil)
		pcapDownloadHandler(mgr).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || rec.Header().Get("Content-Disposition") == "" {
			t.Fatalf("pcap download GET = %d headers=%v", rec.Code, rec.Header())
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodDelete, "/internal/pcap/delete?name="+item.Name, nil)
		pcapDeleteHandler(mgr).ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("pcap delete DELETE = %d", rec.Code)
		}
	})

	t.Run("replay and analyze", func(t *testing.T) {
		item, err := mgr.Upload("analysis.pcap", bytes.NewReader(minimalPCAP()))
		if err != nil {
			t.Fatalf("Upload: %v", err)
		}

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/internal/pcap/replay", bytes.NewBufferString("{"))
		pcapReplayHandler(mgr).ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("pcap replay invalid JSON = %d", rec.Code)
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/internal/pcap/replay", bytes.NewBufferString(`{"name":"`+item.Name+`"}`))
		pcapReplayHandler(mgr).ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("pcap replay missing interface = %d", rec.Code)
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/internal/pcap/replay", bytes.NewBufferString(`{"name":"`+item.Name+`","interface":"eth0","ratePps":50}`))
		pcapReplayHandler(mgr).ServeHTTP(rec, req)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("pcap replay accepted status = %d", rec.Code)
		}
		// The replay handler is async; give it a scheduling slice so the temp-dir-backed
		// upload still exists when Replay opens the file.
		time.Sleep(25 * time.Millisecond)

		var body bytes.Buffer
		writer := multipart.NewWriter(&body)
		part, err := writer.CreateFormFile("file", "analysis.pcap")
		if err != nil {
			t.Fatalf("CreateFormFile: %v", err)
		}
		if _, err := part.Write(minimalPCAP()); err != nil {
			t.Fatalf("write multipart pcap: %v", err)
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("writer.Close: %v", err)
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/internal/pcap/analyze/upload", &body)
		req.Header.Set("Content-Type", writer.FormDataContentType())
		pcapAnalyzeUploadHandler(mgr, nil).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("pcap analyze upload status = %d body=%s", rec.Code, rec.Body.String())
		}
		var analysis map[string]any
		if err := json.NewDecoder(rec.Body).Decode(&analysis); err != nil {
			t.Fatalf("decode analyze upload response: %v", err)
		}
		if got := analysis["packetCount"]; got == nil {
			t.Fatalf("unexpected analyze upload response: %#v", analysis)
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/internal/pcap/analyze/", nil)
		pcapAnalyzeNameHandler(mgr, nil).ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("pcap analyze name missing status = %d", rec.Code)
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/internal/pcap/analyze/missing.pcap", nil)
		pcapAnalyzeNameHandler(mgr, nil).ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("pcap analyze name missing file status = %d", rec.Code)
		}

		rec = httptest.NewRecorder()
		req = httptest.NewRequest(http.MethodPost, "/internal/pcap/analyze/"+item.Name, nil)
		pcapAnalyzeNameHandler(mgr, nil).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("pcap analyze name status = %d body=%s", rec.Code, rec.Body.String())
		}
	})
}
