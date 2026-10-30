// SPDX-License-Identifier: Apache-2.0

package dnp3

import "testing"

func TestDataCRCValid(t *testing.T) {
	for _, payload := range [][]byte{nil, {0xc0, 0xc0, 1}, make([]byte, 40)} {
		raw := linkFrame(0xc4, payload)
		f, err := ParseFrame(raw)
		if err != nil || !f.DataCRCValid() {
			t.Fatalf("valid: %v %v", f, err)
		}
		if len(payload) == 0 {
			continue
		}
		raw[len(raw)-1] ^= 1
		f, err = ParseFrame(raw)
		if err != nil || f.DataCRCValid() {
			t.Fatalf("corrupt: %v %v", f, err)
		}
	}
	if (*DNP3Frame)(nil).DataCRCValid() {
		t.Fatal("nil frame is not validated")
	}
}
