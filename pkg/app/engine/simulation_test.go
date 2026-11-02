// SPDX-License-Identifier: Apache-2.0

package engineapp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	wire "github.com/tonylturner/containd/pkg/common/telemetry"
	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/replay"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/telemetry"
)

// Stage the packaged directory layout, including the original manifest paths
// and verified bytes. A named capture selects a small, real recording for
// behavioral tests without waiting through the full corpus.
func stageDemoCaptures(t *testing.T, name string) string {
	t.Helper()
	root := "../../.."
	raw, err := os.ReadFile(filepath.Join(root, "test/demo/manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var set replay.CaptureSet
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatal(err)
	}
	if name != "" {
		var selected []replay.Capture
		for _, cap := range set.Captures {
			if cap.File == name {
				selected = append(selected, cap)
			}
		}
		if len(selected) != 1 {
			t.Fatalf("capture %s absent", name)
		}
		set.Captures = selected
		raw, err = json.Marshal(set)
		if err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	for _, cap := range set.Captures {
		data, err := os.ReadFile(filepath.Join(root, cap.File))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, cap.File)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONTAIND_DEMO_CAPTURES", dir)
	return dir
}

func newTestSimulation(t *testing.T) *simulationManager {
	t.Helper()
	e, err := engine.New(engine.Config{Events: events.NewStore(128)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	sm := &simulationManager{dpEngine: e}
	t.Cleanup(sm.stop)
	return sm
}

func demoPolicy() rules.Snapshot {
	return rules.Snapshot{Version: "operator-policy", Zones: []string{"mgmt", "dmz", "lan", "wan"},
		Firewall: []rules.Entry{{ID: "operator-deny", Action: rules.ActionDeny,
			ICS: rules.ICSPredicate{Protocol: "modbus", Mode: "enforce"}}},
		IDS: rules.IDSConfig{Enabled: true, Rules: []rules.IDSRule{{
			ID: "operator-ids", Proto: "modbus",
			When: rules.IDSCondition{Field: "kind", Op: "equals", Value: "request"},
		}}},
	}
}

func awaitSimulation(t *testing.T, check func() bool) {
	t.Helper()
	deadline := time.NewTimer(8 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		if check() {
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("timed out waiting for replay")
		case <-tick.C:
		}
	}
}

func TestSimulationWaitingAndCaptureErrors(t *testing.T) {
	sm := newTestSimulation(t)
	if got := sm.status(); got.Running || got.RunID != "" || got.Error != "" {
		t.Fatal(got)
	}
	sm.start()
	if got := sm.status(); got.Running || got.Error != "waiting for policy" {
		t.Fatal(got)
	}
	t.Setenv("CONTAIND_DEMO_CAPTURES", t.TempDir())
	sm.loadRules(demoPolicy())
	if got := sm.status(); got.Running || !strings.HasPrefix(got.Error, "demo captures unavailable: ") {
		t.Fatal(got)
	}
	if got := sm.samples(); len(got) != 0 {
		t.Fatal(got)
	}
	dir := stageDemoCaptures(t, "test/modbus/testdata/diagnostics.pcap")
	// Hash mismatch is a hard error, never a partial replay.
	path := filepath.Join(dir, "test/modbus/testdata/diagnostics.pcap")
	if err := os.WriteFile(path, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	sm.start()
	if got := sm.status(); got.Running || !strings.Contains(got.Error, "sha256 mismatch") {
		t.Fatal(got)
	}
	stageDemoCaptures(t, "test/modbus/testdata/diagnostics.pcap")
	sm.start()
	if got := sm.status(); !got.Running || got.Error != "" {
		t.Fatal(got)
	}
	sm.stop()
	sm.start()
	if !sm.status().Running {
		t.Fatal("could not restart after Stop")
	}
}

func TestSimulationFirstPolicyStartsOnlyWhenRequested(t *testing.T) {
	stageDemoCaptures(t, "test/modbus/testdata/diagnostics.pcap")
	sm := newTestSimulation(t)
	sm.loadRules(demoPolicy())
	if sm.status().Running {
		t.Fatal("policy auto-started replay")
	}
	waiting := newTestSimulation(t)
	waiting.start()
	waiting.loadRules(demoPolicy())
	if !waiting.status().Running {
		t.Fatal("first policy did not satisfy pending Start")
	}
	stopped := newTestSimulation(t)
	stopped.start()
	stopped.stop()
	stopped.loadRules(demoPolicy())
	if stopped.status().Running {
		t.Fatal("policy ignored Stop while waiting")
	}
}

func TestSimulationReplayJoinAndIsolation(t *testing.T) {
	stageDemoCaptures(t, "test/modbus/testdata/diagnostics.pcap")
	sm := newTestSimulation(t)
	e := sm.dpEngine
	e.Events().Append(events.Event{Kind: "real-sentinel"})
	realCounts := e.Events().TelemetryCounts()[0]
	realStats := e.TelemetryTracker().Stats()
	sm.loadRules(demoPolicy())
	sm.start()
	first := sm.status()
	sm.start()
	if got := sm.status(); got.RunID != first.RunID || !got.Running || got.CaptureSet != "containd-demo/1" {
		t.Fatal(got)
	}
	awaitSimulation(t, func() bool {
		for _, ev := range e.Events().ListTelemetry(0) {
			if ev.Origin == wire.OriginDemo && ev.Kind == "ics.decision" &&
				ev.Attributes["ruleId"] == "operator-deny" &&
				(ev.Attributes["decision"] == "would_drop" || ev.Attributes["decision"] == "would_allow") {
				return true
			}
		}
		return false
	})
	awaitSimulation(t, func() bool {
		for _, ev := range e.Events().ListTelemetry(0) {
			if ev.Proto == "ids" && ev.Kind == "alert" && ev.Origin == wire.OriginDemo {
				return true
			}
		}
		return false
	})
	collector := telemetry.Collector{BootID: "boot", Tracker: e.TelemetryTracker, Events: e.Events().TelemetryCounts, Demo: sm.samples}
	awaitSimulation(t, func() bool {
		found := map[wire.Metric]bool{}
		for _, s := range collector.Snapshot(context.Background()).Samples {
			if s.Origin == wire.OriginDemo {
				if s.Epoch != first.RunID {
					t.Fatalf("wrong demo epoch: %+v", s)
				}
				if s.Value > 0 {
					found[s.Metric] = true
				}
			}
		}
		return found[wire.ProtoPackets] && found[wire.IfaceTxPackets] &&
			found[wire.ConduitPackets] && found[wire.EventsTotal]
	})
	sm.mu.Lock()
	worker := sm.active
	sm.mu.Unlock()
	sm.stop()
	for _, done := range []chan struct{}{worker.done, worker.expired} {
		select {
		case <-done:
		default:
			t.Fatal("Stop returned before joining both Run calls")
		}
	}
	before := e.Events().TelemetryCounts()
	privateStats := worker.detached.Stats().Stats()
	progress := worker.counters.Status()
	// Longer than the minimum inter-packet gap: an unjoined replay would
	// append and charge again during this interval.
	time.Sleep(2 * replay.MinGap)
	if !reflect.DeepEqual(before, e.Events().TelemetryCounts()) ||
		!reflect.DeepEqual(privateStats, worker.detached.Stats().Stats()) ||
		progress != worker.counters.Status() {
		t.Fatal("publication or counter charge after Stop")
	}
	if !reflect.DeepEqual(realCounts, e.Events().TelemetryCounts()[0]) || !reflect.DeepEqual(realStats, e.TelemetryTracker().Stats()) {
		t.Fatal("replay changed real events or protocol counters")
	}
	for _, s := range collector.Snapshot(context.Background()).Samples {
		if s.Origin == wire.OriginDemo {
			t.Fatal("stopped replay published demo counters")
		}
	}
	sm.start()
	if got := sm.status(); got.RunID == first.RunID || !got.Running {
		t.Fatalf("restart must have a fresh run epoch: %+v", got)
	}
}

func TestSimulationConcurrentLifecycle(t *testing.T) {
	stageDemoCaptures(t, "test/modbus/testdata/diagnostics.pcap")
	sm := newTestSimulation(t)
	sm.loadRules(demoPolicy())
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 5 {
				sm.start()
				sm.status()
				sm.samples()
				sm.setParsing(map[string]string{"modbus": "strict"})
				sm.loadRules(demoPolicy())
				sm.stop()
			}
		})
	}
	wg.Wait()
	sm.stop()
	if sm.status().Running || len(sm.samples()) != 0 {
		t.Fatal("Stop did not settle concurrent transitions")
	}
}

func TestSimulationRunningUpdates(t *testing.T) {
	stageDemoCaptures(t, "test/modbus/testdata/diagnostics.pcap")
	dp := newCountingDP(t)
	sm := &simulationManager{dpEngine: dp.Engine}
	t.Cleanup(sm.stop)
	c := testProtectionCoordinator(t, dp)
	conf := configHandler(zap.NewNop().Sugar(), dp, sm, c)
	postConfig(t, conf, `{"dpiIcsParsing":{"modbus":"tolerant"}}`)
	dp.waitStart(t)
	apply := applyRulesHandler(dp.Engine, nil, c, sm)
	push := func(snap rules.Snapshot) {
		t.Helper()
		raw, err := json.Marshal(snap)
		if err != nil {
			t.Fatal(err)
		}
		w := coordinatedPost(apply, "test-apply", string(raw))
		if w.Code != http.StatusOK {
			t.Fatalf("rules apply: %d %s", w.Code, w.Body)
		}
	}
	policy := demoPolicy()
	push(policy)
	sm.start()
	first := sm.status()
	sm.mu.Lock()
	worker := sm.active
	sm.mu.Unlock()
	postConfig(t, conf, `{"dpiIcsParsing":{"modbus":"strict"}}`)
	dp.waitStart(t)
	sm.mu.Lock()
	unchanged := sm.active == worker && sm.config.DPIICSParsing["modbus"] == "strict"
	sm.mu.Unlock()
	if !unchanged || sm.status().RunID != first.RunID {
		t.Fatal("parsing-only update rebuilt replay or lost parsing")
	}
	policy.Firewall[0].ID = "replacement-allow"
	policy.Firewall[0].Action = rules.ActionAllow
	push(policy)
	awaitSimulation(t, func() bool {
		for _, ev := range dp.Events().ListTelemetry(0) {
			if ev.Kind == "ics.decision" && ev.Attributes["ruleId"] == "replacement-allow" && ev.Attributes["decision"] == "would_allow" {
				return true
			}
		}
		return false
	})
	if sm.status().RunID != first.RunID {
		t.Fatal("rules-only update restarted replay")
	}
	sig := customSignature("demo-runtime-signature")
	sig.Protocol = "modbus"
	sig.Conditions[0].Value = "request"
	raw, err := json.Marshal(sig)
	if err != nil {
		t.Fatal(err)
	}
	sigs := signaturesHandler(dp.Engine, sm)
	w := httptest.NewRecorder()
	sigs(w, httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(raw)))
	if w.Code != http.StatusOK {
		t.Fatalf("signature add: %d %s", w.Code, w.Body)
	}
	matches := func() int {
		n := 0
		for _, ev := range dp.Events().ListTelemetry(0) {
			if ev.Attributes["signature_id"] == sig.ID {
				n++
			}
		}
		return n
	}
	awaitSimulation(t, func() bool { return matches() > 0 })
	w = httptest.NewRecorder()
	sigs(w, httptest.NewRequest(http.MethodDelete, "/?id="+sig.ID, nil))
	if w.Code != http.StatusNoContent {
		t.Fatalf("signature delete: %d %s", w.Code, w.Body)
	}
	before := matches()
	// Several paced frames after deletion exercise the new signature set.
	time.Sleep(4 * replay.MinGap)
	if matches() != before {
		t.Fatal("deleted signature still active in detached replay")
	}
	policy.Zones = []string{"plant", "outside"}
	push(policy)
	if got := sm.status(); !got.Running || got.RunID == first.RunID {
		t.Fatalf("topology change did not resume with new counter epoch: %+v", got)
	}
	select {
	case <-worker.done:
	default:
		t.Fatal("topology replacement failed to join retired replay")
	}
	awaitSimulation(t, func() bool {
		for _, sample := range sm.samples() {
			if sample.Metric == wire.IfaceTxPackets && sample.Value > 0 {
				if zone := sample.Dims["zone"]; zone != "plant" && zone != "outside" {
					t.Fatalf("old topology samples: %+v", sample)
				}
				return true
			}
		}
		return false
	})
}

func TestSimulationHTTPStatus(t *testing.T) {
	stageDemoCaptures(t, "test/modbus/testdata/diagnostics.pcap")
	sm := newTestSimulation(t)
	sm.loadRules(demoPolicy())
	h := simulationHandler(sm)
	for _, action := range []string{"start", "start", "stop", "stop"} {
		w := httptest.NewRecorder()
		h(w, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"action":"`+action+`"}`)))
		if w.Code != http.StatusOK {
			t.Fatalf("%d: %s", w.Code, w.Body)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(w.Body.Bytes(), &fields); err != nil {
			t.Fatal(err)
		}
		if len(fields) != 6 {
			t.Fatalf("status shape: %s", w.Body)
		}
		for _, key := range []string{"running", "runId", "loops", "captureSet", "capture", "error"} {
			if fields[key] == nil {
				t.Fatalf("missing %s: %s", key, w.Body)
			}
		}
	}
	// Stop is also a barrier through the HTTP handler.
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest(http.MethodGet, "/", bytes.NewReader(nil)))
	if !strings.Contains(w.Body.String(), `"running":false`) {
		t.Fatal(w.Body)
	}
}
