// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package compile

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/iec104"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// euPolicyJSON is the spec §12.4 policy shape: dataplane and the four
// IEC104 rules, as literal JSON.
const euPolicyJSON = `{
  "schema_version": "0.1.7",
  "system": {"hostname": "containd"},
  "zones": [{"name": "lan4"}, {"name": "lan1"}],
  "dataplane": {"dpiEnabled": true, "dpiMode": "enforce", "nfqueueGroup": 101, "nflogGroup": 100,
                "dpiIcsProtocols": {"modbus": true, "iec104": true}},
  "firewall": {"defaultAction": "DENY", "rules": [
    {"id": "cc-rtu-iec104-session", "sourceZones": ["lan4"], "destZones": ["lan1"],
     "sources": ["10.60.60.10/32"], "destinations": ["10.30.30.30/32"],
     "protocols": [{"name": "tcp", "port": "2404"}],
     "ics": {"protocol": "iec104", "readOnly": true, "mode": "enforce"},
     "action": "ALLOW", "log": true},
    {"id": "cc-rtu-breaker-command", "sourceZones": ["lan4"], "destZones": ["lan1"],
     "sources": ["10.60.60.10/32"], "destinations": ["10.30.30.30/32"],
     "protocols": [{"name": "tcp", "port": "2404"}],
     "ics": {"protocol": "iec104", "typeIds": [46], "classes": ["control"],
             "direction": "request", "ca": [1], "ioa": [{"start": 0, "end": 0}, {"start": 65536, "end": 65567}],
             "mode": "enforce"},
     "action": "ALLOW", "log": true},
    {"id": "rtu-cc-command-confirm", "sourceZones": ["lan4"], "destZones": ["lan1"],
     "sources": ["10.60.60.10/32"], "destinations": ["10.30.30.30/32"],
     "protocols": [{"name": "tcp", "port": "2404"}],
     "ics": {"protocol": "iec104", "classes": ["control"], "direction": "response", "mode": "enforce"},
     "action": "ALLOW", "log": true},
    {"id": "deny-other-iec104", "sourceZones": ["lan4"], "destZones": ["lan1"],
     "protocols": [{"name": "tcp", "port": "2404"}],
     "ics": {"protocol": "iec104", "mode": "enforce"},
     "action": "DENY", "log": true}
  ]}
}`

// Spec §10.1 schema bullet: literal JSON → strict decode → validate →
// marshal → compile → engine snapshot JSON → evaluate and preview.
func TestIEC104SchemaPipeline(t *testing.T) {
	var cfg config.Config
	if err := json.Unmarshal([]byte(euPolicyJSON), &cfg); err != nil {
		t.Fatalf("strict decode: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	// GET /config re-emits the input shape: numeric arrays and {start,end}.
	body, err := json.Marshal(cfg.Firewall.Rules[1])
	if err != nil {
		t.Fatalf("marshal rule: %v", err)
	}
	for _, frag := range []string{`"typeIds":[46]`, `"ca":[1]`, `"ioa":[{"start":0,"end":0},{"start":65536,"end":65567}]`} {
		if !strings.Contains(string(body), frag) {
			t.Fatalf("marshalled rule %s lacks %s", body, frag)
		}
	}
	var again config.Rule
	if err := json.Unmarshal(body, &again); err != nil || !reflect.DeepEqual(again, cfg.Firewall.Rules[1]) {
		t.Fatalf("rule round trip = %+v, %v", again, err)
	}

	snap, err := CompileSnapshot(&cfg)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// The management plane sends the snapshot to the engine as JSON
	// (api/engine/client.go ApplyRules); the engine decodes it as-is.
	wire, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	if !strings.Contains(string(wire), `"typeIds":[46]`) {
		t.Fatalf("snapshot JSON must carry typeIds as a numeric array: %s", wire)
	}
	var engineSnap rules.Snapshot
	if err := json.Unmarshal(wire, &engineSnap); err != nil {
		t.Fatalf("engine decode: %v", err)
	}
	if !reflect.DeepEqual(engineSnap.Firewall, snap.Firewall) {
		t.Fatalf("engine snapshot differs:\n%+v\n%+v", engineSnap.Firewall, snap.Firewall)
	}

	ev := rules.NewEvaluator(&engineSnap)
	session := func(direction string, obj rules.IEC104Context) rules.EvalContext {
		return rules.EvalContext{
			SrcZone: "lan4", DstZone: "lan1",
			SrcIP: net.ParseIP("10.60.60.10"), DstIP: net.ParseIP("10.30.30.30"),
			Proto: "tcp", Port: "2404",
			ICS: &rules.ICSContext{Protocol: "iec104", Direction: direction, IEC104: &obj},
		}
	}
	u8 := func(v uint8) *uint8 { return &v }
	u16 := func(v uint16) *uint16 { return &v }
	u32 := func(v uint32) *uint32 { return &v }
	command := func(ioa uint32) rules.IEC104Context {
		return rules.IEC104Context{APCIType: "I", TypeID: u8(46), CA: u16(1), IOA: u32(ioa), Class: "control"}
	}
	cases := []struct {
		name      string
		direction string
		obj       rules.IEC104Context
		want      rules.Action
	}{
		{"IOA 0 is a real address", "request", command(0), rules.ActionAllow},
		{"IOA above 65535", "request", command(65567), rules.ActionAllow},
		{"IOA 1 is outside both ranges", "request", command(1), rules.ActionDeny},
		{"confirmation", "response", command(1), rules.ActionAllow},
		{"GI", "request", rules.IEC104Context{APCIType: "I", TypeID: u8(100), CA: u16(1), IOA: u32(0), Class: "system", SafeRead: true}, rules.ActionAllow},
	}
	for _, tc := range cases {
		if got, _ := ev.EvaluateIEC104(session(tc.direction, tc.obj)); got != tc.want {
			t.Errorf("%s: EvaluateIEC104 = %s, want %s", tc.name, got, tc.want)
		}
	}
	if in, mode := ev.IEC104Envelope(session("", rules.IEC104Context{}), cfg.DataPlane.DPIMode); !in || mode != "enforce" {
		t.Fatalf("envelope = %v, %q; want true, enforce", in, mode)
	}
	if !rules.PreviewMatch(engineSnap.Firewall[1], session("request", command(65536))) {
		t.Fatal("PreviewMatch must match the compiled command rule")
	}

	// The same policy is rejected before save when the decoder is off.
	cfg.DataPlane.DPIICSProtocols["iec104"] = false
	if _, err := CompileSnapshot(&cfg); err == nil || !strings.Contains(err.Error(), "dpiIcsProtocols.iec104") {
		t.Fatalf("compile with the decoder off err = %v, want E3 rejection", err)
	}
}

// Both shipped RangerDanger US policies still compile (spec §6.2).
func TestRangerDangerUSPoliciesCompile(t *testing.T) {
	for _, name := range []string{"substation-weak.json", "substation-improved.json"} {
		raw, err := os.ReadFile(filepath.Join("..", "config", "testdata", "rangerdanger", name))
		if err != nil {
			t.Fatal(err)
		}
		var cfg config.Config
		if err := json.Unmarshal(raw, &cfg); err != nil {
			t.Fatalf("%s: decode: %v", name, err)
		}
		if _, err := CompileSnapshot(&cfg); err != nil {
			t.Fatalf("%s: compile: %v", name, err)
		}
	}
}

func TestIEC104MonitorClassAndGIKeepPolicySessionAllowed(t *testing.T) {
	const policy = `{
	  "schema_version":"0.1.7",
	  "system":{"hostname":"containd"},
	  "zones":[{"name":"lan4"},{"name":"lan1"}],
	  "dataplane":{"dpiEnabled":true,"dpiMode":"enforce","nfqueueGroup":101,
	    "dpiIcsProtocols":{"iec104":true}},
	  "firewall":{"defaultAction":"DENY","rules":[
	    {"id":"monitor","sourceZones":["lan4"],"destZones":["lan1"],
	     "sources":["10.60.60.10/32"],"destinations":["10.30.30.30/32"],
	     "protocols":[{"name":"tcp","port":"2404"}],
	     "ics":{"protocol":"iec104","classes":["monitor"],"direction":"response","mode":"enforce"},
	     "action":"ALLOW"},
	    {"id":"gi","sourceZones":["lan4"],"destZones":["lan1"],
	     "sources":["10.60.60.10/32"],"destinations":["10.30.30.30/32"],
	     "protocols":[{"name":"tcp","port":"2404"}],
	     "ics":{"protocol":"iec104","typeIds":[100],"readOnly":true,"mode":"enforce"},
	     "action":"ALLOW"},
	    {"id":"deny-other","sourceZones":["lan4"],"destZones":["lan1"],
	     "protocols":[{"name":"tcp","port":"2404"}],
	     "ics":{"protocol":"iec104","mode":"enforce"},"action":"DENY"}
	  ]}
	}`
	var cfg config.Config
	if err := json.Unmarshal([]byte(policy), &cfg); err != nil {
		t.Fatalf("decode policy: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate policy: %v", err)
	}
	snap, err := CompileSnapshot(&cfg)
	if err != nil {
		t.Fatalf("compile policy: %v", err)
	}
	evaluator := rules.NewEvaluator(&snap)

	const ca = 1
	cp56 := []byte{0x29, 0x09, 15, 9, 7, 11, 26}
	client := pipelineIFrame(100, 6, 1, ca, 0, []byte{20})
	server := catPipeline(
		pipelineIFrame(100, 7, 1, ca, 0, []byte{20}),
		pipelineIFrame(1, 20, 1, ca, 1, []byte{1}),
		pipelineIFrame(3, 20, 1, ca, 2, []byte{2}),
		pipelineIFrame(5, 20, 1, ca, 1301, []byte{0xC2, 0x90}),
		pipelineIFrame(13, 20, 1, ca, 3, []byte{0, 0, 0xC0, 0x3F, 0}),
		pipelineIFrame(100, 10, 1, ca, 0, []byte{20}),
		pipelineIFrame(30, 3, 1, ca, 1, append([]byte{1}, cp56...)),
		pipelineIFrame(31, 3, 1, ca, 2, append([]byte{2}, cp56...)),
		pipelineIFrame(32, 3, 1, ca, 1301, append([]byte{0xC2, 0x90}, cp56...)),
		pipelineIFrame(2, 3, 1, ca, 4, []byte{1}),
	)

	state := flow.NewState(flow.Key{Proto: 6, SrcPort: 40000, DstPort: iec104.Port}, time.Now())
	decoder := iec104.NewDecoder()
	traffic := []struct {
		dir   dpi.StreamDir
		bytes []byte
	}{
		{dpi.ClientToServer, client},
		{dpi.ServerToClient, server},
	}
	seen := make(map[uint8]int)
	for _, stream := range traffic {
		res, err := decoder.ParseStream(state, dpi.StreamView{
			Session: "pipeline-session", Dir: stream.dir, Bytes: stream.bytes,
		})
		if err != nil || res.Consumed != len(stream.bytes) || res.NeedMore {
			t.Fatalf("decode direction %d: consumed %d/%d needMore=%v err=%v",
				stream.dir, res.Consumed, len(stream.bytes), res.NeedMore, err)
		}
		for _, frame := range res.Frames {
			for _, ev := range frame.Events {
				attrs := ev.Attributes
				ctx := rules.IEC104Context{
					Malformed:   ev.Kind == eventfields.KindMalformed,
					Unsupported: ev.Kind == eventfields.KindUnsupported,
				}
				ctx.APCIType, _ = eventfields.String(attrs, eventfields.KeyAPCIType)
				ctx.Class, _ = eventfields.String(attrs, eventfields.KeyClass)
				ctx.SafeRead = iec104.SafeRead(attrs)
				if v, ok := eventfields.Uint8(attrs, eventfields.KeyTypeID); ok {
					ctx.TypeID = &v
					seen[v]++
				}
				if v, ok := eventfields.Uint16(attrs, eventfields.KeyCA); ok {
					ctx.CA = &v
				}
				if v, ok := eventfields.Uint32(attrs, eventfields.KeyIOA); ok {
					ctx.IOA = &v
				}
				direction, _ := eventfields.String(attrs, eventfields.KeyDirection)
				evalCtx := rules.EvalContext{
					SrcZone: "lan4", DstZone: "lan1",
					SrcIP: net.ParseIP("10.60.60.10"), DstIP: net.ParseIP("10.30.30.30"),
					Proto: "tcp", Port: "2404",
					ICS: &rules.ICSContext{Protocol: "iec104", Direction: direction, IEC104: &ctx},
				}
				action, entry := evaluator.EvaluateIEC104(evalCtx)
				if ev.Kind == eventfields.KindUnsupported {
					if action != rules.ActionDeny {
						t.Errorf("unsupported TypeID %v got %s by %v, want DENY", ctx.TypeID, action, entry)
					}
					continue
				}
				if action != rules.ActionAllow || entry == nil {
					t.Errorf("%s TypeID %v direction %s got %s by %v, want ALLOW",
						ev.Kind, ctx.TypeID, direction, action, entry)
				}
			}
		}
	}
	for _, typeID := range []uint8{1, 3, 5, 13, 30, 31, 32, 100} {
		if seen[typeID] == 0 {
			t.Errorf("policy traffic did not include TypeID %d", typeID)
		}
	}
	if seen[2] != 1 {
		t.Errorf("unsupported TypeID 2 decoded %d times, want once and DENY", seen[2])
	}
}

func pipelineIFrame(typeID, cause, vsq uint8, ca uint16, ioa uint32, element []byte) []byte {
	asdu := []byte{typeID, vsq, cause, 0}
	asdu = binary.LittleEndian.AppendUint16(asdu, ca)
	asdu = append(asdu, byte(ioa), byte(ioa>>8), byte(ioa>>16))
	asdu = append(asdu, element...)
	frame := []byte{0x68, byte(4 + len(asdu)), 0, 0, 0, 0}
	return append(frame, asdu...)
}

func catPipeline(frames ...[]byte) []byte {
	var out []byte
	for _, frame := range frames {
		out = append(out, frame...)
	}
	return out
}
