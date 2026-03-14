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
