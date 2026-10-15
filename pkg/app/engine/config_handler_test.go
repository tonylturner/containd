// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/engine"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// countingDP is the real engine with its Reconfigure and StartWithRetry
// calls counted. startFn, when set, replaces the next starts.
type countingDP struct {
	*engine.Engine
	reconfigs atomic.Int32
	starts    atomic.Int32
	mu        sync.Mutex
	startFn   func(context.Context) error
	results   chan error
}

func newCountingDP(t *testing.T) *countingDP {
	t.Helper()
	e, err := engine.New(engine.Config{})
	if err != nil {
		t.Fatal(err)
	}
	return &countingDP{Engine: e, results: make(chan error, 64)}
}

func (c *countingDP) Reconfigure(fresh *engine.Engine) {
	c.reconfigs.Add(1)
	c.Engine.Reconfigure(fresh)
}

func (c *countingDP) StartWithRetry(ctx context.Context) error {
	c.starts.Add(1)
	c.mu.Lock()
	fn := c.startFn
	c.startFn = nil
	c.mu.Unlock()
	var err error
	if fn != nil {
		err = fn(ctx)
	} else {
		err = c.Engine.StartWithRetry(ctx)
	}
	c.results <- err
	return err
}

func (c *countingDP) waitStart(t *testing.T) error {
	t.Helper()
	select {
	case err := <-c.results:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("the handler did not start the engine")
		return nil
	}
}

func postConfig(t *testing.T, h http.Handler, body string) map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/internal/config", bytes.NewBufferString(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST %s = %d %s", body, rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out["status"] != "configured" {
		t.Fatalf("POST response = %s (%v)", rec.Body.String(), err)
	}
	return out
}

var (
	ccIP  = net.ParseIP("10.60.60.10")
	rtuIP = net.ParseIP("10.30.30.30")
)

func iecPacket(fromClient bool, flags capture.TCPFlags, seq, ack uint32, payload []byte) capture.Packet {
	p := capture.Packet{Timestamp: time.Now().UTC(), Proto: 6, Transport: "tcp", Payload: payload,
		TCP: capture.TCPMeta{Valid: true, Seq: seq, Ack: ack, Flags: flags}}
	if fromClient {
		p.SrcIP, p.DstIP, p.SrcPort, p.DstPort = ccIP, rtuIP, 40000, 2404
	} else {
		p.SrcIP, p.DstIP, p.SrcPort, p.DstPort = rtuIP, ccIP, 2404, 40000
	}
	return p
}

// spontaneous is an M_DP_NA_1 (type 3) spontaneous APDU from the RTU with
// send sequence ns.
func spontaneous(ns uint16) []byte {
	return []byte{0x68, 0x0e, byte(ns << 1), byte(ns >> 7), 0, 0, 3, 1, 3, 0, 1, 0, 0xe9, 0x03, 0, 0x02}
}

// iecSessionIDs returns the session IDs of IEC104 decoder events in the ring.
func iecSessionIDs(e *engine.Engine) map[string]int {
	out := map[string]int{}
	for _, ev := range e.Events().List(0) {
		if ev.Proto == "iec104" && ev.Kind == "response" {
			id, _ := ev.Attributes["session_id"].(string)
			out[id]++
		}
	}
	return out
}

func TestConfigUnchangedKeepsEngineState(t *testing.T) {
	dp := newCountingDP(t)
	sim := &simulationManager{dpEngine: dp.Engine, logger: zap.NewNop().Sugar()}
	h := configHandler(zap.NewNop().Sugar(), dp, sim)
	learn := `{"dpiEnabled":true,"dpiMode":"learn","dpiIcsProtocols":{"iec104":true}}`
	if out := postConfig(t, h, learn); out["unchanged"] != false || dp.reconfigs.Load() != 1 {
		t.Fatalf("first POST must rebuild: %v reconfigs=%d", out, dp.reconfigs.Load())
	}
	dp.waitStart(t)
	dp.LoadRules(rules.Snapshot{Firewall: []rules.Entry{{ID: "iec-learn", Action: rules.ActionAllow,
		ICS: rules.ICSPredicate{Protocol: "iec104", Mode: "learn"}}}})

	// Engine state: a stored event, an inventory entry, a live IEC104 session.
	dp.Events().Append(dpevents.Event{Proto: "dns", Kind: "query", Timestamp: time.Now().UTC(), FlowID: "marker"})
	dp.Inventory().RecordEvent("192.0.2.10", "192.0.2.20", dpi.Event{Proto: "modbus", Timestamp: time.Now(),
		Attributes: map[string]any{"unit_id": uint8(1), "function_code": uint8(3)}})
	for _, p := range []capture.Packet{
		iecPacket(true, capture.TCPFlagSYN, 999, 0, nil),
		iecPacket(false, capture.TCPFlagSYN|capture.TCPFlagACK, 4999, 1000, nil),
		iecPacket(true, capture.TCPFlagACK, 1000, 5000, nil),
		iecPacket(false, capture.TCPFlagACK|capture.TCPFlagPSH, 5000, 1000, spontaneous(0)),
	} {
		if d := dp.HandlePacket(p); d.Action != capture.Accept {
			t.Fatalf("packet %+v = %+v", p.TCP, d)
		}
	}
	ids := iecSessionIDs(dp.Engine)
	if len(ids) != 1 {
		t.Fatalf("IEC104 sessions before = %v", ids)
	}
	var session string
	for id := range ids {
		session = id
	}

	out := postConfig(t, h, learn)
	if out["unchanged"] != true || dp.reconfigs.Load() != 1 {
		t.Fatalf("unchanged POST rebuilt: %v reconfigs=%d", out, dp.reconfigs.Load())
	}
	dp.waitStart(t)
	if dp.starts.Load() != 2 {
		t.Fatalf("starts = %d, want the unchanged POST to start too", dp.starts.Load())
	}
	found := false
	for _, ev := range dp.Events().List(0) {
		found = found || ev.FlowID == "marker"
	}
	if !found || len(dp.Inventory().List()) == 0 {
		t.Fatalf("event marker=%v inventory=%d after an unchanged POST", found, len(dp.Inventory().List()))
	}
	dp.HandlePacket(iecPacket(false, capture.TCPFlagACK|capture.TCPFlagPSH, 5016, 1000, spontaneous(1)))
	if got := iecSessionIDs(dp.Engine)[session]; got != 2 {
		t.Fatalf("session %s events = %d after an unchanged POST, want 2 (still parsed, no reset)", session, got)
	}
	for _, ev := range dp.Events().List(0) {
		if ev.Kind == "ics.session" {
			t.Fatalf("unexpected session outcome: %+v", ev)
		}
	}

	// A changed configuration rebuilds inventory and the session table,
	// but preserves the process event ring. Old session data is not parsed.
	store := dp.Events()
	before := iecSessionIDs(dp.Engine)[session]
	out = postConfig(t, h, `{"dpiEnabled":true,"dpiMode":"learn","dpiIcsProtocols":{"iec104":true},"dpiProtocols":{"dns":false}}`)
	if out["unchanged"] != false || dp.reconfigs.Load() != 2 {
		t.Fatalf("changed POST did not rebuild: %v reconfigs=%d", out, dp.reconfigs.Load())
	}
	dp.waitStart(t)
	if dp.Events() != store || len(dp.Events().List(0)) == 0 || len(dp.Inventory().List()) != 0 {
		t.Fatal("a rebuild must preserve events but reset inventory")
	}
	dp.HandlePacket(iecPacket(false, capture.TCPFlagACK|capture.TCPFlagPSH, 5032, 1000, spontaneous(2)))
	if got := iecSessionIDs(dp.Engine)[session]; got != before {
		t.Fatalf("old session still parsed after a rebuild: events %d -> %d", before, got)
	}
}

func TestConfigChangedKeepsEventsAndRecordsNewIECSession(t *testing.T) {
	dp := newCountingDP(t)
	sim := &simulationManager{dpEngine: dp.Engine, logger: zap.NewNop().Sugar()}
	h := configHandler(zap.NewNop().Sugar(), dp, sim)
	store := dp.Events()
	postConfig(t, h, `{"dpiEnabled":true,"dpiMode":"learn","dpiIcsProtocols":{"iec104":true}}`)
	dp.waitStart(t)
	dp.LoadRules(rules.Snapshot{Firewall: []rules.Entry{{ID: "iec-learn", Action: rules.ActionAllow,
		ICS: rules.ICSPredicate{Protocol: "iec104", Mode: "learn"}}}})
	marker := store.Append(dpevents.Event{Kind: "firewall.rule.hit", Timestamp: time.Now().UTC(),
		Attributes: map[string]any{"action": "DENY"}, FlowID: "before-rebuild"})
	postConfig(t, h, `{"dpiEnabled":true,"dpiMode":"learn","dpiIcsProtocols":{"iec104":true},"dpiProtocols":{"dns":false}}`)
	dp.waitStart(t)
	if dp.Events() != store {
		t.Fatal("rebuild replaced the store")
	}
	for _, p := range []capture.Packet{
		iecPacket(true, capture.TCPFlagSYN, 999, 0, nil),
		iecPacket(false, capture.TCPFlagSYN|capture.TCPFlagACK, 4999, 1000, nil),
		iecPacket(true, capture.TCPFlagACK, 1000, 5000, nil),
		iecPacket(false, capture.TCPFlagACK|capture.TCPFlagPSH, 5000, 1000, spontaneous(0)),
	} {
		if d := dp.HandlePacket(p); d.Action != capture.Accept {
			t.Fatalf("packet %+v = %+v", p.TCP, d)
		}
	}
	rec := httptest.NewRecorder()
	eventsHandler(dp.Engine).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/internal/events", nil))
	var listed []dpevents.Event
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &listed) != nil {
		t.Fatalf("events response = %d %s", rec.Code, rec.Body.String())
	}
	var foundMarker, foundIEC bool
	for _, ev := range listed {
		foundMarker = foundMarker || ev.ID == marker.ID && ev.FlowID == marker.FlowID
		if ev.Proto == "iec104" && ev.Kind == "response" {
			foundIEC = true
			if ev.ID <= marker.ID {
				t.Fatalf("IEC event ID %d did not advance past %d", ev.ID, marker.ID)
			}
		}
	}
	if !foundMarker || !foundIEC {
		t.Fatalf("events after rebuild: marker=%v IEC104=%v: %+v", foundMarker, foundIEC, listed)
	}
}

func TestConfigEqualityIsExact(t *testing.T) {
	dp := newCountingDP(t)
	h := configHandler(zap.NewNop().Sugar(), dp, &simulationManager{dpEngine: dp.Engine, logger: zap.NewNop().Sugar()})
	steps := []struct {
		body      string
		unchanged bool
	}{
		{`{}`, false}, // the first POST always rebuilds, even for the zero config
		{`{}`, true},
		{`{"captureInterfaces":["a","b"]}`, false},
		{`{"captureInterfaces":["a","b"]}`, true},
		{`{"captureInterfaces":["b","a"]}`, false}, // order-sensitive
		{`{"captureInterfaces":["b","a"],"dpiIcsProtocols":{"modbus":true,"iec104":true}}`, false},
		{`{"captureInterfaces":["b","a"],"dpiIcsProtocols":{"iec104":true,"modbus":true}}`, true}, // map key order is not a change
		{`{"captureInterfaces":["b","a"],"dpiIcsProtocols":{"iec104":true,"modbus":false}}`, false},
		{`{"captureInterfaces":["b","a"],"dpiIcsProtocols":{"iec104":true,"modbus":false},"dpiExclusions":[{"value":"10.0.0.1","type":"ip"}]}`, false},
		{`{"captureInterfaces":["b","a"],"dpiIcsProtocols":{"iec104":true,"modbus":false},"dpiExclusions":[{"value":"10.0.0.1","type":"cidr"}]}`, false},
	}
	for i, s := range steps {
		if got := postConfig(t, h, s.body)["unchanged"]; got != s.unchanged {
			t.Fatalf("step %d %s: unchanged = %v, want %v", i, s.body, got, s.unchanged)
		}
		dp.waitStart(t)
	}
}

func TestConfigInvalidEngineDoesNotRecordApplied(t *testing.T) {
	dp := newCountingDP(t)
	h := configHandler(zap.NewNop().Sugar(), dp, &simulationManager{dpEngine: dp.Engine, logger: zap.NewNop().Sugar()})
	postConfig(t, h, `{}`)
	dp.waitStart(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/internal/config", bytes.NewBufferString(`{"dpiMode":`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid JSON = %d", rec.Code)
	}
	if got := postConfig(t, h, `{}`)["unchanged"]; got != true {
		t.Fatalf("a rejected POST must not change the applied config (unchanged=%v)", got)
	}
	dp.waitStart(t)
}

func TestConfigUnchangedRetriesAStartThatGaveUp(t *testing.T) {
	dp := newCountingDP(t)
	h := configHandler(zap.NewNop().Sugar(), dp, &simulationManager{dpEngine: dp.Engine, logger: zap.NewNop().Sugar()})
	gaveUp := errors.New("nfqueue 101: giving up after 8 bind attempts")
	dp.startFn = func(context.Context) error { return gaveUp }
	postConfig(t, h, `{"dpiEnabled":true}`)
	if err := dp.waitStart(t); !errors.Is(err, gaveUp) {
		t.Fatalf("first start = %v", err)
	}
	if out := postConfig(t, h, `{"dpiEnabled":true}`); out["unchanged"] != true || dp.reconfigs.Load() != 1 {
		t.Fatalf("second POST = %v reconfigs=%d", out, dp.reconfigs.Load())
	}
	if err := dp.waitStart(t); err != nil {
		t.Fatalf("the unchanged POST did not start the engine: %v", err)
	}
}

func TestConfigUnchangedKeepsTheSimulationRunning(t *testing.T) {
	dp := newCountingDP(t)
	sim := &simulationManager{dpEngine: dp.Engine, logger: zap.NewNop().Sugar()}
	t.Cleanup(sim.stop)
	h := configHandler(zap.NewNop().Sugar(), dp, sim)
	run := func() string {
		sim.mu.Lock()
		defer sim.mu.Unlock()
		if !sim.running {
			return ""
		}
		return fmt.Sprintf("run %d", sim.runs)
	}
	postConfig(t, h, `{"dpiMock":true}`)
	dp.waitStart(t)
	first := run()
	if first == "" {
		t.Fatal("DPI mock did not start the simulation")
	}
	postConfig(t, h, `{"dpiMock":true}`)
	dp.waitStart(t)
	if run() != first {
		t.Fatal("an unchanged POST restarted the simulation")
	}
	postConfig(t, h, `{"dpiMock":true,"dpiMode":"learn"}`)
	dp.waitStart(t)
	if now := run(); now == "" || now == first {
		t.Fatal("a changed POST must restart the simulation")
	}
	postConfig(t, h, `{"dpiMode":"learn"}`)
	dp.waitStart(t)
	if run() != "" {
		t.Fatal("turning the DPI mock off must stop the simulation")
	}
}

func TestConfigConcurrentGetAndPost(t *testing.T) {
	dp := newCountingDP(t)
	h := configHandler(zap.NewNop().Sugar(), dp, &simulationManager{dpEngine: dp.Engine, logger: zap.NewNop().Sugar()})
	go func() {
		for range dp.results {
		}
	}()
	var wg sync.WaitGroup
	bodies := []string{`{"dpiMode":"learn"}`, `{"dpiMode":"enforce"}`}
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/internal/config", bytes.NewBufferString(bodies[(i+j)%2])))
				if rec.Code != http.StatusOK {
					t.Errorf("POST = %d", rec.Code)
				}
			}
		}(i)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/internal/config", nil))
				var got map[string]any
				if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil {
					t.Errorf("GET = %d %s", rec.Code, rec.Body.String())
				}
			}
		}()
	}
	wg.Wait()
}
