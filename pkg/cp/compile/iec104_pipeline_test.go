// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package compile

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
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
