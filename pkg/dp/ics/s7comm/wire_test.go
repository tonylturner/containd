// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package s7comm

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

func TestDecoderStandardCOTPData(t *testing.T) {
	// Independently laid out ISO-on-TCP fixture: RFC 1006 §6 TPKT (03 00,
	// big-endian total length), ITU-T X.224 §13.7 DT (02 F0 80), then an S7 Setup
	// Communication job (32 01, reference 1, eight parameter octets).
	// No production constants or packet builders define the wire bytes.
	wire, err := hex.DecodeString("0300001902f08032010000000100080000f0000001000101e0")
	if err != nil {
		t.Fatal(err)
	}
	state := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 50000, 102), time.Now())
	events, err := NewDecoder().OnPacket(state, &dpi.ParsedPacket{Payload: wire})
	if err != nil || len(events) != 1 {
		t.Fatalf("standard DT: events=%+v, err=%v", events, err)
	}
	ev := events[0]
	if ev.Proto != "s7comm" || ev.Kind != "request" ||
		ev.Attributes["function_code"] != uint8(0xf0) ||
		ev.Attributes["function_name"] != "setup_communication" {
		t.Fatalf("unexpected service decoding: %+v", ev)
	}

	// The old nibble-swapped byte is not a DT TPDU.
	wire[5] = 0x0f
	events, err = NewDecoder().OnPacket(state, &dpi.ParsedPacket{Payload: wire})
	if err != nil || len(events) != 0 {
		t.Fatalf("nibble-swapped type: events=%+v, err=%v", events, err)
	}
}

func TestDecoderCOTPConnectionCredit(t *testing.T) {
	// ITU-T X.224 §13.3/§13.4: the high nibble identifies CR/CC; the low
	// nibble is CDT (credit), not part of the TPDU code. Exercise all credits.
	for _, code := range []byte{0xe0, 0xd0} {
		for credit := byte(0); credit < 16; credit++ {
			wire := []byte{0x03, 0x00, 0x00, 0x0b, 0x06, code | credit, 0, 0, 0, 1, 0}
			state := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 50000, 102), time.Now())
			events, err := NewDecoder().OnPacket(state, &dpi.ParsedPacket{Payload: wire})
			if err != nil || len(events) != 1 {
				t.Fatalf("CR/CC %02x: events=%+v, err=%v", code|credit, events, err)
			}
			if events[0].Kind != "connection" || events[0].Attributes["cotp_pdu_type"] != code|credit {
				t.Fatalf("CR/CC %02x: unexpected event %+v", code|credit, events[0])
			}
		}
	}
}
