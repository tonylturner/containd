// SPDX-License-Identifier: Apache-2.0
package cip

import (
	"slices"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields/decodertest"
)

func TestOperationTargetEmission(t *testing.T) {
	for _, tc := range []struct {
		name, wire, target string
		symbol             []string
	}{
		{"logical", "0e03200124013002", "logical", nil},
		{"16-bit logical", "0e0621003412250078563100bc9a", "logical", nil},
		{"class only", "08012001", "logical", nil},
		{"member", "1803200424012801", "logical", nil},
		{"connection point", "0e03200424012c01", "logical", nil},
		{"16-bit connection point", "0e04200424012d003412", "logical", nil},
		{"symbol", "4c02910254470100", "symbolic", []string{"TG"}},
		{"symbol elements", "4c069103544147002801290002000100", "symbolic", []string{"TAG"}},
		{"symbol subtree", "4c05910254472801910241420100", "symbolic", []string{"TG", "AB"}},
		{"program symbol", "4c0a910c50726f6772616d3a4d61696e91044d6f746f0100", "symbolic", []string{"Program:Main", "Moto"}},
		{"response has no target", "8e000000", "", nil},
		{"no path", "0e00", "unknown", nil},
		{"32-bit class", "0e042200000001002401", "unknown", nil},
		{"32-bit instance", "0e042001260000000100", "unknown", nil},
		{"32-bit attribute", "0e0520012401320000000100", "unknown", nil},
		{"32-bit element", "4c05910254472a00000001000100", "unknown", nil},
		{"logical symbolic mix", "4c04206b2401910254470100", "unknown", nil},
		{"symbolic logical mix", "4c039102544720010100", "unknown", nil},
		{"repeated instance", "0e03200124012402", "unknown", nil},
		{"repeated attribute", "0e042001240130013002", "unknown", nil},
		{"repeated member", "18042004240128012802", "unknown", nil},
		{"multiple terminal segments", "18042004240130012801", "unknown", nil},
		{"repeated connection point", "0e04200424012c012c02", "unknown", nil},
		{"port", "0e03200124010100", "unknown", nil},
		{"key", "0e03200124013400", "unknown", nil},
		{"data", "0e03200124018000", "unknown", nil},
		{"truncated declared path", "0e0320012401", "unknown", nil},
		{"bad symbol padding", "4c039103544147010100", "unknown", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Standalone and MSP children use the same target authority.
			wire := requestBytes(t, tc.wire)
			for _, ev := range []dpi.Event{wireEvents(t, wire)[0], wireEvents(t, mspWire(0x0a, wire))[1]} {
				for form, attrs := range decodertest.Forms(t, ev.Attributes) {
					target, ok := eventfields.String(attrs, eventfields.KeyCIPTarget)
					symbol, hasSymbol := eventfields.Strings(attrs, eventfields.KeyCIPSymbol)
					if ok != (tc.target != "") || target != tc.target || hasSymbol != (tc.symbol != nil) || !slices.Equal(symbol, tc.symbol) {
						t.Fatalf("%s target=%v symbol=%v attrs=%v", form, target, symbol, attrs)
					}
					if _, present := attrs[eventfields.KeyCoverageIncomplete]; present {
						t.Fatalf("%s standalone/child operation has no hidden operations: %v", form, attrs)
					}
				}
			}
		})
	}
}

func assertEmissionCoverage(t *testing.T, ev dpi.Event, want bool) {
	t.Helper()
	for form, attrs := range decodertest.Forms(t, ev.Attributes) {
		incomplete, present := eventfields.Bool(attrs, eventfields.KeyCoverageIncomplete)
		if present != want || incomplete != want {
			t.Fatalf("%s coverage=%v present=%v want=%v attrs=%v", form, incomplete, present, want, attrs)
		}
	}
}

func TestMSPCoverageEmission(t *testing.T) {
	leaf := requestBytes(t, "0e03200124013001")
	limited := make([][]byte, maxMSPServices+1)
	for i := range limited {
		limited[i] = leaf
	}
	deep := leaf
	for range maxMSPDepth + 2 {
		deep = mspWire(0x0a, deep)
	}
	for _, tc := range []struct {
		name       string
		wire       []byte
		incomplete bool
	}{
		{"complete", mspWire(0x0a, leaf, mspWire(0x0a, leaf)), false},
		{"empty complete", mspWire(0x0a), false},
		{"response complete", mspWire(0x8a, []byte{0x8e, 0, 0, 0}), false},
		{"error response", []byte{0x8a, 0, 1, 0}, false},
		{"missing count", []byte{0x0a, 0}, true},
		{"missing table", []byte{0x0a, 0, 1, 0}, true},
		{"missing child", []byte{0x0a, 0, 1, 0, 4, 0}, true},
		{"empty with trailing data", []byte{0x0a, 0, 0, 0, 0}, true},
		// A gap is incomplete even when declared == decoded.
		{"layout gap", []byte{0x0a, 0, 1, 0, 6, 0, 0, 0, 0x4c, 0}, true},
		{"nested layout", mspWire(0x0a, mspWire(0x0a, []byte{0x0a, 0, 1, 0}), leaf), true},
		{"service budget", mspWire(0x0a, limited...), true},
		{"nested service budget", mspWire(0x0a, mspWire(0x0a, limited...), leaf), true},
		{"depth budget", deep, true},
		{"truncated wrapper path", []byte{0x0a, 3, 0x20, 2}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			evs := wireEvents(t, tc.wire)
			for _, ev := range evs {
				service, _ := eventfields.Uint8(ev.Attributes, eventfields.KeyFunctionCode)
				assertEmissionCoverage(t, ev, tc.incomplete && service == 0x0a)
				if service == 0x0a {
					if _, present := ev.Attributes[eventfields.KeyIsWrite]; present {
						t.Fatal("wrapper has an access category")
					}
				}
			}
		})
	}
}

func TestExtraCPFDataCoverageEmission(t *testing.T) {
	leaf := requestBytes(t, "0e03200124013001")
	for _, root := range [][]byte{leaf, mspWire(0x0a, leaf)} {
		for _, id := range []uint16{0xb1, 0xb2} {
			for _, truncated := range []bool{false, true} {
				body := buildCPFItems(cpfTestItem{0, nil}, cpfTestItem{0xb2, root}, cpfTestItem{id, leaf})
				if truncated {
					body = body[:len(body)-1]
				}
				evs := encapsulationEvents(cipState(), &EIPHeader{Command: 0x6f, Data: body})
				for i, ev := range evs {
					assertEmissionCoverage(t, ev, i == 0)
				}
			}
		}
	}
	for _, id := range []uint16{0xc, 0x100, 0x8000} {
		body := buildCPFItems(cpfTestItem{0, nil}, cpfTestItem{0xb2, leaf}, cpfTestItem{id, make([]byte, 16)})
		assertEmissionCoverage(t, encapsulationEvents(cipState(), &EIPHeader{Command: 0x6f, Data: body})[0], false)
	}
}

func TestMSPCoverageDoesNotLeakIntoSiblingWrappers(t *testing.T) {
	leaf := requestBytes(t, "0e03200124013001")
	evs := wireEvents(t, mspWire(0x0a, []byte{0x0a, 0, 1, 0}, mspWire(0x0a, leaf)))
	if len(evs) != 4 {
		t.Fatal(evs)
	}
	for i, ev := range evs {
		assertEmissionCoverage(t, ev, i < 2)
	}
}

func TestConnectionPointTargetDoesNotInventAccess(t *testing.T) {
	for _, wire := range []string{"0e03200424012c01", "4c03206b24012c010100"} {
		ev := wireEvents(t, requestBytes(t, wire))[0]
		if ev.Attributes[eventfields.KeyCIPTarget] != "logical" {
			t.Fatal(ev)
		}
		for _, key := range []string{eventfields.KeyIsWrite, "is_control"} {
			if _, present := ev.Attributes[key]; present {
				t.Fatalf("connection-point operation gained an unverified access category: %v", ev)
			}
		}
	}
}
