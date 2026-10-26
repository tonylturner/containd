// SPDX-License-Identifier: Apache-2.0
//go:build linux

package netcfg

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestRuleOwnershipIsProtocolNotPriority(t *testing.T) {
	for _, priority := range []uint32{1, 100, 10000, 15000, 19999, 40000, 65535} {
		for _, protocol := range []uint8{0, unix.RTPROT_STATIC, routeProtoContaind} {
			var data bytes.Buffer
			_ = binary.Write(&data, binary.LittleEndian, fibRuleHdr{Family: unix.AF_INET, Table: 201, Action: frActToTbl})
			p := make([]byte, 4)
			binary.LittleEndian.PutUint32(p, priority)
			addRtAttr(&data, fraPriority, p)
			addRtAttr(&data, fraProtocol, []byte{protocol})
			r, ok := decodeKernelRule(data.Bytes(), int(unsafe.Sizeof(fibRuleHdr{})))
			if !ok || (r.proto == routeProtoContaind) != (protocol == routeProtoContaind) {
				t.Fatalf("priority %d protocol %d ownership=%v", priority, protocol, ok)
			}
			if ok && (r.priority != priority || r.proto != protocol) {
				t.Fatalf("decoded %+v", r)
			}
		}
	}
}

func TestRouteIntentRetainsKernelResolvedInterface(t *testing.T) {
	want := kernelRoute{dst: net.ParseIP("198.18.2.0"), dstLen: 24, gateway: net.ParseIP("198.18.0.2"), table: 254, proto: routeProtoContaind}
	got := want
	got.ifIndex = 42
	if !routeMatchesIntent(got, want) {
		t.Fatal("gateway-only route must retain kernel-selected OIF")
	}
	want.ifIndex = 43
	if routeMatchesIntent(got, want) {
		t.Fatal("explicit interface change must not match")
	}
}
