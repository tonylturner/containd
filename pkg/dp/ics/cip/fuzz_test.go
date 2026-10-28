// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cip

import "testing"

func FuzzParseEIPHeader(f *testing.F) {
	valid := buildEIPHeader(0x006F, 0x12345678, buildSendRRDataPayload(0x4C, 1, []byte{0x20, 0x02}))

	f.Add([]byte{})
	f.Add([]byte{0x6F, 0x00})
	f.Add(valid)

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseEIPHeader(data)
	})
}

func FuzzParseCIPMessage(f *testing.F) {
	readTag := buildSendRRDataPayload(0x4C, 1, []byte{0x20, 0x02})
	response := buildSendRRDataPayload(0xCC, 1, []byte{0x20, 0x02})
	msp := buildSendRRDataPayload(0x0A, 1, []byte{0x20, 0x02})

	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add(readTag)
	f.Add(response)
	f.Add(msp)
	f.Add(buildCPFItems(cpfTestItem{0x00a1, []byte{1, 0, 0, 0}}, cpfTestItem{0x00b1, []byte{1, 0, 0x4c, 0}}))
	f.Add(buildCPFItems(cpfTestItem{0x00b2, []byte{0x4c, 0}}, cpfTestItem{0x1234, []byte{1}}))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseCIPMessage(data)
		_ = ParseMSPServices(data)
		_ = ParseEPath(data)
	})
}
