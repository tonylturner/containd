// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package opcua

import (
	"encoding/binary"
	"testing"
)

func FuzzParseFrame(f *testing.F) {
	validHEL := make([]byte, 32)
	copy(validHEL[0:3], "HEL")
	validHEL[3] = 'F'
	binary.LittleEndian.PutUint32(validHEL[4:8], 32)

	validMSG := make([]byte, 28)
	copy(validMSG[0:3], "MSG")
	validMSG[3] = 'F'
	binary.LittleEndian.PutUint32(validMSG[4:8], 28)
	validMSG[24] = 0x01
	validMSG[25] = 0x00
	binary.LittleEndian.PutUint16(validMSG[26:28], ServiceReadRequest)

	f.Add([]byte{})
	f.Add([]byte("MS"))
	f.Add(validHEL)
	f.Add(validMSG)

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseFrame(data)
	})
}
