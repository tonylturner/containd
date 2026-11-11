// SPDX-License-Identifier: Apache-2.0

package itdpi

import "testing"

func FuzzHTTP2Stream(f *testing.F) {
	valid := append(h2Settings(), h2Frame(1, 4, 1, h2RequestBlock())...)
	f.Add(valid)
	f.Add(h2Frame(1, 4, 0, []byte{0x88}))
	f.Add(append(h2Settings(), h2Frame(1, 12, 1, []byte{4})...))
	f.Add(append(h2Settings(), h2Frame(9, 4, 1, []byte{0xff})...))
	f.Add([]byte{1, 0, 0, 1, 4, 0, 0, 0, 1})
	f.Fuzz(func(t *testing.T, data []byte) {
		raw := append([]byte(h2Preface), data...)
		fuzzITStream(raw, NewHTTPDecoder(), httpFlowState(12345, 80))
	})
}
