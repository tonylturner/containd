// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engine

import (
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
)

// TestFirstCommandAfterConflictingOverlap resends the not yet framed head
// of a read with different bytes, as a client with a raw socket can. The
// server's TCP stack keeps the bytes it received first and discards the
// overlap, so its stream is the read followed by the prohibited command.
// The engine must still drop the segment that completes that command.
//
// The conflict is a stream error. Were the stream restarted at the next
// segment's first byte, the decoder would frame from the middle of the
// read and the complete prohibited command would pass; an enforce flow
// fails closed instead.
func TestFirstCommandAfterConflictingOverlap(t *testing.T) {
	for _, tc := range []struct {
		name    string
		port    uint16
		read    []byte
		command []byte
	}{
		// Transaction ID 0x00FE: the misframed MBAP length field.
		{"modbus fc6 write", 502, modbusADU(1, 3, 0, 2), modbusADU(0x00FE, 6, 1, 0x1234)},
		{"dnp3 fc5 direct operate", dnp3Port, dnp3Request(1, 1, []byte{0x3C, 0x01, 0x06}), dnp3Operate(5, 9)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFCFlow(t, "ok", tc.port)
			f.syn()
			f.accept("read head", tc.read[:8])
			conflict := append([]byte(nil), tc.read[:8]...)
			conflict[4] ^= 0xFF
			// The overlap is not new data for the server; its verdict is
			// not the property under test.
			f.decide(0, ackPsh, conflict)
			if d := f.decide(8, ackPsh, concatFrames(tc.read[8:], tc.command)); d.Action != capture.Drop {
				t.Fatalf("after a conflicting overlap the segment completing %s = %+v, want Drop", tc.name, d)
			}
		})
	}
}
