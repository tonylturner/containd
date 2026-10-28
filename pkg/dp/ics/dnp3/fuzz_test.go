// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package dnp3

import (
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields/decodertest"
)

func FuzzParseFrame(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x05, 0x64})
	f.Add(buildTestFrame(0x0A, 0xC0, 0x0001, 0x0002, []byte{0xC0, 0xC0, 0x01, 0x1E, 0x02}))
	f.Add(buildTestFrame(0x0C, 0x44, 0x0002, 0x0001, []byte{0xC0, 0xC0, 0x81, 0x00, 0x00, 0x1E, 0x02}))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseFrame(data)
	})
}

func FuzzParseObjectHeaders(f *testing.F) {
	f.Add([]byte{1}, uint8(FuncRead))
	f.Add([]byte{1, 2}, uint8(FuncRead))
	f.Add([]byte{0x01, 0x02, 0x06, 0x1E, 0x02, 0x00, 0x00, 0x04}, uint8(FuncRead))
	f.Add([]byte{0x46, 0x03, 0x5B, 0x01, 0x03, 0x00, 0xAA, 0xBB, 0xCC}, uint8(0x19))
	f.Add([]byte{0x01, 0x01, 0x00, 0x00, 0x09, 0xFF, 0x03}, uint8(FuncResponse))

	f.Fuzz(func(t *testing.T, data []byte, fc uint8) {
		headers, stop := parseObjectHeaders(data, 0, fc)
		for i, h := range headers {
			if h.Offset < 0 || h.Offset >= len(data) || h.Covered < 1 || h.Covered > len(data)-h.Offset {
				t.Fatalf("invalid coverage %+v for %d bytes", h, len(data))
			}
			// A stopped walk deliberately retains a readable partial final header.
			if stop != walkComplete && i == len(headers)-1 {
				continue
			}
			if h.Size < 3 || h.Size > len(data)-h.Offset || h.Covered < h.Size {
				t.Fatalf("invalid complete header %+v", h)
			}
		}
	})
}

func FuzzParseStream(f *testing.F) {
	f.Add(concat(readFrame, linkStatus), uint16(0))
	f.Add(concat(operateFrame, continuation, readFrame[:11]), uint16(3))
	f.Add([]byte{0x05, 0x64, 0x05, 0xC0, 1, 0, 2, 0, 0xFF, 0xFF}, uint16(1))

	state := dnp3State()
	f.Fuzz(func(t *testing.T, data []byte, base uint16) {
		decodertest.CheckStreamFactory(t, func() dpi.StreamDecoder { return NewDecoder() }, state, dpi.StreamView{Session: "fuzz", Base: int64(base), Bytes: data})
	})
}
