// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package s7comm

import "testing"

func FuzzParseTPKT(f *testing.F) {
	job := buildFullPacket(MsgTypeJob, 0x0100, []byte{FuncReadVar}, nil)
	ack := buildFullPacket(MsgTypeAckData, 0x0001, []byte{FuncReadVar}, nil)

	f.Add([]byte{})
	f.Add([]byte{0x03, 0x00})
	f.Add(job)
	f.Add(ack)

	f.Fuzz(func(t *testing.T, data []byte) {
		hdr, rem, _ := ParseTPKT(data)
		if hdr == nil || len(rem) == 0 {
			return
		}

		_, cotpPayload, _ := ParseCOTP(rem)
		if len(cotpPayload) == 0 {
			return
		}

		h, _ := ParseS7Header(cotpPayload)
		if h != nil {
			_, _ = ParseS7VarItems(cotpPayload, h)
		}
	})
}
