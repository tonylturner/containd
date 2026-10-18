// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package iec104

import (
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields/decodertest"
)

// The read-only set of spec §6.1 with W7, on real decoded events, in memory
// and after a JSON round trip.
func TestSafeRead(t *testing.T) {
	gi := cat(ioa(0), []byte{20})
	cases := []struct {
		name  string
		dir   dpi.StreamDir
		frame []byte
		want  bool
	}{
		{"S-frame from client", cli, sFrame(1), true},
		{"S-frame from server", srv, sFrame(1), true},
		{"STARTDT act", cli, uFrame(startdtAct), true},
		{"STOPDT act", cli, uFrame(stopdtAct), true},
		{"TESTFR act from server", srv, uFrame(testfrAct), true},
		{"monitor 1 response", srv, iFrame(0, 0, asdu(1, 1, cotSpont, 0, 1, cat(ioa(1002), []byte{0x91})...)), true},
		{"monitor 3 response", srv, iFrame(0, 0, asdu(3, 1, cotSpont, 0, 1, cat(ioa(1), []byte{1})...)), true},
		{"monitor 13 response", srv, iFrame(0, 0, asdu(13, 1, cotInrogen, 0, 1, cat(ioa(1), f32(1), []byte{0})...)), true},
		{"monitor 30 response", srv, iFrame(0, 0, asdu(30, 1, cotSpont, 0, 1, cat(ioa(1002), []byte{0x91}, courseTime)...)), true},
		{"monitor 31 response", srv, iFrame(0, 0, asdu(31, 1, cotSpont, 0, 1, cat(ioa(1), []byte{1}, courseTime)...)), true},
		{"GI request", cli, iFrame(0, 0, asdu(100, 1, cotAct, 0, 1, gi...)), true},
		{"GI confirmation", srv, iFrame(0, 0, asdu(100, 1, cotActCon, 0, 1, gi...)), true},
		{"GI termination", srv, iFrame(0, 0, asdu(100, 1, cotActTerm, 0, 1, gi...)), true},
		{"read request", cli, iFrame(0, 0, asdu(102, 1, cotRequest, 0, 1, ioa(1)...)), true},
		{"end of initialization", srv, iFrame(0, 0, asdu(70, 1, cotInit, 0, 1, cat(ioa(0), []byte{0})...)), true},

		{"read response is an error (W7)", srv, iFrame(0, 0, asdu(102, 1, 47|bitNegative, 0, 1, ioa(1)...)), false},
		{"counter interrogation", cli, iFrame(0, 0, asdu(101, 1, cotAct, 0, 1, cat(ioa(0), []byte{5})...)), false},
		{"clock sync", cli, iFrame(0, 0, asdu(103, 1, cotAct, 0, 1, cat(ioa(0), courseTime)...)), false},
		{"reset process", cli, iFrame(0, 0, asdu(105, 1, cotAct, 0, 1, cat(ioa(0), []byte{1})...)), false},
		{"test with time", cli, iFrame(0, 0, asdu(107, 1, cotAct, 0, 1, cat(ioa(0), []byte{1, 0}, courseTime)...)), false},
		{"single command", cli, iFrame(0, 0, asdu(45, 1, cotAct, 0, 1, cat(ioa(1), []byte{1})...)), false},
		{"double command", cli, iFrame(0, 0, asdu(46, 1, cotAct, 0, 1, cat(ioa(1), []byte{1})...)), false},
		{"command confirmation", srv, iFrame(0, 0, asdu(46, 1, cotActCon, 0, 1, cat(ioa(1), []byte{1})...)), false},
		{"broadcast GI", cli, iFrame(0, 0, asdu(100, 1, cotAct, 0, BroadcastCA, gi...)), false},
		{"broadcast monitor data", srv, iFrame(0, 0, asdu(3, 1, cotSpont, 0, BroadcastCA, cat(ioa(1), []byte{1})...)), false},
		{"malformed (role)", cli, iFrame(0, 0, asdu(3, 1, cotSpont, 0, 1, cat(ioa(1), []byte{1})...)), false},
		{"malformed S-frame length", srv, []byte{0x68, 6, 0x01, 0x00, 0x02, 0x00, 0, 0}, false},
		{"unsupported", srv, iFrame(0, 0, asdu(2, 1, cotSpont, 0, 1, cat(ioa(1), []byte{1})...)), false},
	}
	for _, tc := range cases {
		evs := events(parseOne(t, tc.dir, tc.frame))
		if len(evs) != 1 {
			t.Fatalf("%s: %d events", tc.name, len(evs))
		}
		for form, attrs := range decodertest.Forms(t, evs[0].Attributes) {
			if got := SafeRead(attrs); got != tc.want {
				t.Errorf("%s (%s): SafeRead = %v, want %v", tc.name, form, got, tc.want)
			}
		}
	}
	if SafeRead(nil) || SafeRead(map[string]any{"apci_type": "I", "type_id": uint8(3), "direction": "response"}) {
		t.Fatal("SafeRead without CA")
	}
}
