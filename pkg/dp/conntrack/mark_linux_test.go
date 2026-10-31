// SPDX-License-Identifier: Apache-2.0
//go:build linux

package conntrack

import (
	"context"
	"encoding/binary"
	"testing"
)

func TestMarkClearRequest(t *testing.T) {
	record := ctRecord("192.0.2.1", "192.0.2.2", 1234)
	record = append(record, nlAttrU32(ctaMark, 0xa532ff03)...)
	record = append(record, nlAttrU32(ctaID, 123)...)
	record = append(record, nlAttrU16(ctaZone, 7)...)
	out, err := markClearRequest(record, 3, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	a, err := attributes(out[4:])
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint32(a[ctaMark]) != 0 || binary.BigEndian.Uint32(a[ctaMarkMask]) != 2 ||
		binary.BigEndian.Uint32(a[ctaID]) != 123 || binary.BigEndian.Uint16(a[ctaZone]) != 7 || len(a[1]) == 0 {
		t.Fatalf("bad masked update: %x", out)
	}
	for _, match := range []struct{ mask, value, clear uint32 }{{3, 1, 2}, {3, 3, 4}} {
		out, err := markClearRequest(record, match.mask, match.value, match.clear)
		if err != nil || out != nil {
			t.Fatalf("nonmatching/already clear entry: %x %v", out, err)
		}
	}
	missingID := append(ctRecord("192.0.2.1", "192.0.2.2", 1234), nlAttrU32(ctaMark, 2)...)
	for _, bad := range [][]byte{nil, {2, 0, 0, 0, 1}, missingID} {
		if _, err := markClearRequest(bad, 0, 0, 2); err == nil {
			t.Fatal("accepted malformed record")
		}
	}
}

func TestClearMarkRejectsInvalidMasks(t *testing.T) {
	for _, args := range [][3]uint32{{1, 2, 1}, {1, 1, 0}} {
		if _, err := ClearMark(context.Background(), args[0], args[1], args[2]); err == nil {
			t.Fatal("accepted invalid mask/value")
		}
	}
}
