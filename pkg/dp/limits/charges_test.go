// SPDX-License-Identifier: Apache-2.0

package limits

import "testing"

func TestMetadataCharges(t *testing.T) {
	for _, n := range []int64{StreamMetadataBytes, BindingMetadataBytes, DecoderMetadataBytes, DNP3StationMetadataBytes, IECSessionMetadataBytes, HeldTokenMetadataBytes, PairingMetadataBytes, HeldPacketHeaderAllowanceBytes} {
		if n <= 0 {
			t.Fatal("metadata must reserve credit")
		}
	}
	if IECSessionMetadataBytes > 4096 || MaxIECSessions*IECSessionMetadataBytes > DefaultMaxInspectionBytes/4 {
		t.Fatal("IEC metadata consumes enforcement headroom")
	}
}
