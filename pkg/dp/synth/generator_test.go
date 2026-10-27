// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package synth

import (
	"context"
	"encoding/hex"
	"math/rand"
	"slices"
	"strings"
	"testing"
	"time"

	dpevents "github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
)

func TestDefaultConfigAndSubnets(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.EventsPerSecond != 4 {
		t.Fatalf("EventsPerSecond = %v", cfg.EventsPerSecond)
	}
	if len(cfg.Subnets) != 4 {
		t.Fatalf("DefaultConfig subnets = %#v", cfg.Subnets)
	}

	defaults := DefaultSubnets()
	if len(defaults) != 4 || defaults[0].Zone != "wan" || defaults[1].Zone != "dmz" {
		t.Fatalf("DefaultSubnets = %#v", defaults)
	}
}

func TestPrefixAndSubnetsFromInterfaces(t *testing.T) {
	if got := prefixFromCIDR("192.168.100.12/24"); got != "192.168.100." {
		t.Fatalf("prefixFromCIDR ipv4 = %q", got)
	}
	if got := prefixFromCIDR("not-a-cidr"); got != "" {
		t.Fatalf("prefixFromCIDR invalid = %q", got)
	}
	if got := prefixFromCIDR("2001:db8::1/64"); got != "" {
		t.Fatalf("prefixFromCIDR ipv6 = %q", got)
	}

	subs := SubnetsFromInterfaces([]IfaceSummary{
		{Zone: "wan", Address: "203.0.113.2/24"},
		{Zone: "lan", Address: "192.0.2.2/24"},
		{Zone: "mgmt", Address: ""},
		{Zone: "lan", Address: "192.0.2.3/24"},
	})
	if len(subs) != 3 {
		t.Fatalf("SubnetsFromInterfaces = %#v", subs)
	}
	if subs[0].Prefix != "203.0.113." || subs[1].Prefix != "192.0.2." {
		t.Fatalf("unexpected derived prefixes: %#v", subs)
	}
	if subs[2].Prefix == "" || !strings.HasPrefix(subs[2].Prefix, "10.") {
		t.Fatalf("expected fallback prefix, got %#v", subs[2])
	}

	if got := SubnetsFromInterfaces(nil); len(got) != len(DefaultSubnets()) {
		t.Fatalf("expected fallback default subnets, got %#v", got)
	}
}

func TestGeneratorNextAndModbusHelpers(t *testing.T) {
	g := &generator{
		rng: rand.New(rand.NewSource(7)),
		cfg: Config{
			EventsPerSecond: 2,
			Subnets: []Subnet{
				{Zone: "wan", Prefix: "203.0.113."},
				{Zone: "lan", Prefix: "192.0.2."},
			},
		},
		subnets: []Subnet{
			{Zone: "wan", Prefix: "203.0.113."},
			{Zone: "lan", Prefix: "192.0.2."},
		},
	}

	ev := g.next()
	if ev.Proto == "" || ev.Kind == "" || ev.FlowID == "" {
		t.Fatalf("next event = %#v", ev)
	}
	if ev.Attributes["srcZone"] == ev.Attributes["dstZone"] {
		t.Fatalf("expected cross-zone synthetic flow, got %#v", ev.Attributes)
	}
	if ev.SrcIP == "" || ev.DstIP == "" || ev.Transport == "" {
		t.Fatalf("unexpected next event fields: %#v", ev)
	}

	reqAttrs := synthModbusRequest(rand.New(rand.NewSource(1)))
	if reqAttrs["raw_hex"] == "" || reqAttrs["function_code"] == nil || reqAttrs["unit_id"] == nil {
		t.Fatalf("synthModbusRequest attrs = %#v", reqAttrs)
	}
	if _, err := hex.DecodeString(reqAttrs["raw_hex"].(string)); err != nil {
		t.Fatalf("request raw_hex invalid: %v", err)
	}

	exAttrs := synthModbusException(rand.New(rand.NewSource(2)))
	if exAttrs["exception_code"] == nil || exAttrs["exception_description"] == nil {
		t.Fatalf("synthModbusException attrs = %#v", exAttrs)
	}
	if _, err := hex.DecodeString(exAttrs["raw_hex"].(string)); err != nil {
		t.Fatalf("exception raw_hex invalid: %v", err)
	}

	frame := modbusFrame(0x1234, 7, 3, []byte{0x00, 0x10, 0x00, 0x01})
	if len(frame) != 12 {
		t.Fatalf("modbusFrame len = %d", len(frame))
	}
	if frame[0] != 0x12 || frame[1] != 0x34 || frame[6] != 7 || frame[7] != 3 {
		t.Fatalf("unexpected modbusFrame header = %v", frame[:8])
	}

	tlsAttrs := synthTLSClientHello(rand.New(rand.NewSource(3)))
	if tlsAttrs["sni"] == nil || tlsAttrs["tls_version"] == nil || tlsAttrs["ja3_hash"] == nil {
		t.Fatalf("synthTLSClientHello attrs = %#v", tlsAttrs)
	}
}

func TestRunGeneratesEventsAndCallsCallback(t *testing.T) {
	store := dpevents.NewStore(16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		Run(ctx, store, Config{
			EventsPerSecond: 1000,
			Subnets: []Subnet{
				{Zone: "wan", Prefix: "203.0.113."},
				{Zone: "lan", Prefix: "192.0.2."},
			},
			OnEvent: func(ev dpevents.Event) {
				if ev.Proto == "" || ev.FlowID == "" {
					t.Errorf("unexpected callback event: %#v", ev)
				}
				cancel()
			},
		})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop after callback cancellation")
	}

	events := store.List(10)
	if len(events) == 0 {
		t.Fatal("expected synthetic event to be appended")
	}
	if events[0].Proto == "" || events[0].FlowID == "" {
		t.Fatalf("unexpected stored event: %#v", events[0])
	}
}

// TestSynthModbusRequestShapes requires each synthetic request to carry the
// decoder's fields for its function code and a span the policy can bound.
func TestSynthModbusRequestShapes(t *testing.T) {
	want := map[uint8][]string{
		1: {"address", "quantity"}, 2: {"address", "quantity"},
		3: {"address", "quantity"}, 4: {"address", "quantity"},
		5: {"address", "value"}, 6: {"address", "value"},
		15: {"address", "quantity", "byte_count"}, 16: {"address", "quantity", "byte_count"},
		23: {"read_address", "read_quantity", "write_address", "write_quantity", "byte_count"},
		8:  {"sub_function", "sub_function_name"},
		43: {"mei_type", "mei_type_name"},
	}
	dataKeys := []string{"address", "quantity", "value", "byte_count", "register_count",
		"and_mask", "or_mask", "read_address", "read_quantity", "write_address", "write_quantity"}
	seen := map[uint8]bool{}
	rng := rand.New(rand.NewSource(11))
	for i := 0; i < 2000; i++ {
		attrs := synthModbusRequest(rng)
		fc, ok := eventfields.Uint8(attrs, "function_code")
		keys, known := want[fc]
		if !ok || !known {
			t.Fatalf("unexpected function code in %v", attrs)
		}
		seen[fc] = true
		for _, k := range keys {
			if _, ok := attrs[k]; !ok {
				t.Fatalf("FC %d lacks %q: %v", fc, k, attrs)
			}
		}
		for _, k := range dataKeys {
			if _, ok := attrs[k]; ok && !slices.Contains(keys, k) {
				t.Fatalf("FC %d carries %q: %v", fc, k, attrs)
			}
		}
		if isWrite, _ := eventfields.Bool(attrs, "is_write"); isWrite != (modbus.IsWriteFunctionCode(fc) || attrs["sub_function"] == uint16(1)) {
			t.Fatalf("FC %d is_write = %v: %v", fc, isWrite, attrs)
		}
		if _, ok := modbus.AddressSpans(attrs); !ok {
			t.Fatalf("FC %d request has no bounded span: %v", fc, attrs)
		}
	}
	if len(seen) != len(want) {
		t.Fatalf("function codes generated = %v, want all of %v", seen, want)
	}
}
