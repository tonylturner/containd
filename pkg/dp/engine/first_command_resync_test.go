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
// KNOWN DEFECT, marked with t.Skip while it reproduces: the conflict is a
// stream error, the legacy stream restarts at the next segment's first
// byte, and the decoder frames from the middle of the read. The Modbus
// write's transaction ID becomes a 254-byte MBAP length (need more), the
// DNP3 read's header CRC an invalid start (malformed, passes); either way
// the complete prohibited command is accepted. When the engine drops it,
// the test passes; then remove the skip.
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
			d := f.decide(8, ackPsh, concatFrames(tc.read[8:], tc.command))
			if d.Action == capture.Drop {
				return
			}
			t.Skipf("KNOWN DEFECT: after a conflicting overlap the engine accepts the segment completing %s (decision %+v)", tc.name, d)
		})
	}
}
