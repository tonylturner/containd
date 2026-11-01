// SPDX-License-Identifier: Apache-2.0
//go:build linux

package capture

import (
	"encoding/binary"
	"net/netip"
	"testing"

	nfqueue "github.com/florianl/go-nfqueue/v2"
)

type metadataAttribute struct {
	Type uint16
	Data []byte
}

func metadataAttrs(t *testing.T, attrs ...metadataAttribute) []byte {
	t.Helper()
	var data []byte
	for _, a := range attrs {
		n := 4 + len(a.Data)
		b := make([]byte, (n+3)&^3)
		binary.NativeEndian.PutUint16(b, uint16(n))
		binary.NativeEndian.PutUint16(b[2:], a.Type)
		copy(b[4:], a.Data)
		data = append(data, b...)
	}
	return data
}

func metadataU32(n uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	return b
}

func TestQueueConntrackDecode(t *testing.T) {
	tuple := metadataAttrs(t,
		metadataAttribute{Type: 1 | 0x8000, Data: metadataAttrs(t,
			metadataAttribute{Type: 1, Data: []byte{198, 51, 100, 5}},
			metadataAttribute{Type: 2, Data: []byte{203, 0, 113, 2}})},
		metadataAttribute{Type: 2 | 0x8000, Data: metadataAttrs(t,
			metadataAttribute{Type: 1, Data: []byte{17}},
			metadataAttribute{Type: 2, Data: []byte{0, 0}},
			metadataAttribute{Type: 3, Data: []byte{5, 220}})})
	raw := metadataAttrs(t, metadataAttribute{Type: 1 | 0x8000, Data: tuple},
		metadataAttribute{Type: 8, Data: metadataU32(0x123)},
		metadataAttribute{Type: 3, Data: metadataU32(0x80)})
	info := uint32(3)
	ct, err := decodeQueueConntrack(raw, &info)
	if err != nil {
		t.Fatal(err)
	}
	if !ct.HasMark || ct.Mark != 0x123 || !ct.HasStatus || ct.Status != 0x80 || !ct.DirectionKnown || !ct.IsReply {
		t.Fatalf("metadata: %+v", ct)
	}
	if ct.Original.Source != netip.MustParseAddrPort("198.51.100.5:0") ||
		ct.Original.Destination != netip.MustParseAddrPort("203.0.113.2:1500") || ct.Reply.Source.IsValid() {
		t.Fatalf("tuple: %+v", ct)
	}
	missing, err := decodeQueueConntrack(nil, nil)
	if err != nil || missing.HasMark || missing.HasStatus || missing.DirectionKnown || missing.Original.Source.IsValid() {
		t.Fatalf("missing fields invented: %+v %v", missing, err)
	}
	m := queueMetadata(nfqueue.Attribute{})
	if m.Conntrack != nil || m.HasHook || m.IngressDevice != "" || m.EgressDevice != "" {
		t.Fatalf("missing queue evidence invented: %+v", m)
	}
}

func TestQueueConntrackRejectsMalformed(t *testing.T) {
	for _, raw := range [][]byte{
		{1, 0, 0}, {3, 0, 1, 0},
		metadataAttrs(t, metadataAttribute{Type: 8, Data: []byte{1}}),
		metadataAttrs(t, metadataAttribute{Type: 8, Data: metadataU32(1)}, metadataAttribute{Type: 8, Data: metadataU32(2)}),
	} {
		if _, err := decodeQueueConntrack(raw, nil); err == nil {
			t.Fatalf("accepted malformed metadata %x", raw)
		}
	}
	info := uint32(7)
	if _, err := decodeQueueConntrack(nil, &info); err == nil {
		t.Fatal("untracked metadata accepted")
	}
}
