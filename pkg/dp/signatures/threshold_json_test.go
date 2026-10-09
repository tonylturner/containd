// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package signatures

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

func builtin(t *testing.T, id string) Signature {
	t.Helper()
	for _, s := range builtinSignatures() {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("no built-in %s", id)
	return Signature{}
}

func TestThresholdJSONShapeAndBuiltinRoundTrip(t *testing.T) {
	storm := builtin(t, "MODBUS-EXCEPTION-STORM")
	raw, err := json.Marshal(storm)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"count": float64(10), "windowSeconds": float64(60)}
	if got := wire["threshold"]; !reflect.DeepEqual(got, want) {
		t.Fatalf("threshold JSON = %v, want %v", got, want)
	}
	var back Signature
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, storm) || back.Threshold.Window() != time.Minute {
		t.Fatalf("round trip = %+v, want %+v", back, storm)
	}
	// Signatures without a threshold do not emit the key.
	raw, err = json.Marshal(builtin(t, "MODBUS-SCAN-001"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "threshold") {
		t.Fatalf("threshold emitted for a plain signature: %s", raw)
	}
}

func TestCustomThresholdSignatureFromJSON(t *testing.T) {
	const custom = `[{"id":"CUSTOM-WRITE-BURST","name":"Write burst","protocol":"modbus","severity":"high",
		"conditions":[{"field":"is_write","op":"equals","value":true}],
		"threshold":{"count":3,"windowSeconds":5}}]`
	e := New()
	if err := e.LoadFromJSON(strings.NewReader(custom)); err != nil {
		t.Fatal(err)
	}
	sigs := e.List()
	if len(sigs) != 1 || sigs[0].Threshold == nil || *sigs[0].Threshold != (Threshold{Count: 3, WindowSeconds: 5}) {
		t.Fatalf("loaded = %+v", sigs)
	}
	raw, err := json.Marshal(sigs)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"threshold":{"count":3,"windowSeconds":5}`) {
		t.Fatalf("re-marshalled = %s", raw)
	}
	t0 := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	alerts := 0
	for i := 0; i < 6; i++ {
		ev := dpi.Event{Proto: "modbus", Kind: "request", FlowID: "f", Timestamp: t0.Add(time.Duration(i) * time.Second),
			Attributes: map[string]any{"is_write": true}}
		alerts += len(e.Match(ev))
	}
	// Writes at t=0..2 fire at the third; t=3..5 continue the 5 s window.
	if alerts != 1 {
		t.Fatalf("alerts = %d, want 1", alerts)
	}
}

func TestInvalidThresholdIsRejected(t *testing.T) {
	for _, th := range []string{`{"count":1,"windowSeconds":60}`, `{"count":10,"windowSeconds":0}`, `{"count":10}`, `{}`} {
		in := `[{"id":"OK","conditions":[{"field":"kind","op":"equals","value":"x"}]},
			{"id":"BAD","conditions":[{"field":"kind","op":"equals","value":"x"}],"threshold":` + th + `}]`
		e := New()
		if err := e.LoadFromJSON(strings.NewReader(in)); err == nil || !strings.Contains(err.Error(), "BAD") {
			t.Fatalf("threshold %s: err = %v", th, err)
		}
		if len(e.List()) != 0 {
			t.Fatalf("threshold %s: a rejected array added signatures", th)
		}
	}
}
