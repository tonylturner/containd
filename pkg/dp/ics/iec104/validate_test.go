// SPDX-License-Identifier: Apache-2.0

package iec104

import "testing"

func TestValidateAPDU(t *testing.T) {
	for _, tc := range []struct {
		name           string
		b              []byte
		size           int
		supported, bad bool
	}{
		{"partial", []byte{0x68, 4, 7}, 0, false, false},
		{"start", []byte{1}, 0, false, true},
		{"U", []byte{0x68, 4, 7, 0, 0, 0}, 6, true, false},
		{"S", []byte{0x68, 4, 1, 0, 0, 0}, 6, true, false},
		{"reserved", []byte{0x68, 4, 7, 1, 0, 0}, 6, false, true},
		{"function", []byte{0x68, 4, 3, 0, 0, 0}, 6, false, true},
		{"weak I", []byte{0x68, 4, 0, 0, 0, 0}, 6, false, true},
		{"I", []byte{0x68, 14, 0, 0, 0, 0, 1, 1, 3, 0, 1, 0, 1, 0, 0, 1}, 16, true, false},
		{"unknown I", []byte{0x68, 10, 0, 0, 0, 0, 200, 1, 3, 0, 1, 0}, 12, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, err := ValidateAPDU(tc.b)
			if (err != nil) != tc.bad || v.Size != tc.size || v.Supported != tc.supported {
				t.Fatalf("%+v err=%v", v, err)
			}
		})
	}
}
