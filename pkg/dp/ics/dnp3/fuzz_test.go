// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package dnp3

import "testing"

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
	f.Add([]byte{0x01, 0x02, 0x06, 0x1E, 0x02, 0x00, 0x00, 0x04}, uint8(FuncRead))
	f.Add([]byte{0x46, 0x03, 0x5B, 0x01, 0x03, 0x00, 0xAA, 0xBB, 0xCC}, uint8(0x19))
	f.Add([]byte{0x01, 0x01, 0x00, 0x00, 0x09, 0xFF, 0x03}, uint8(FuncResponse))

	f.Fuzz(func(t *testing.T, data []byte, fc uint8) {
		pos := 0
		for _, h := range ParseObjectHeaders(data, 0, fc) {
			if h.Size < 3 || pos+h.Size > len(data) {
				t.Fatalf("header %+v overruns %d bytes at %d", h, len(data), pos)
			}
			pos += h.Size
		}
	})
}
