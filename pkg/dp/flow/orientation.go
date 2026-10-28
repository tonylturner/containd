// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package flow

import (
	"net"
	"strconv"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/ics"
)

// ICSServiceDirection is a midstream hint, used only without handshake or
// connection evidence. Equal-status ports are ambiguous: callers retain
// first-seen orientation, not a proved client/server assignment.
func ICSServiceDirection(proto uint8, srcPort, dstPort uint16) (Direction, bool) {
	src, dst := ics.IsDecoderPortOn(proto, srcPort), ics.IsDecoderPortOn(proto, dstPort)
	if src == dst {
		return DirForward, false
	}
	if src {
		return DirReverse, true
	}
	return DirForward, true
}

// ParseKey recovers the directional connection key retained in a DPI FlowID.
// Session IDs and noncanonical or invalid tuple hashes are not flow keys.
func ParseKey(id string) (Key, bool) {
	parts := strings.Split(id, "|")
	if len(parts) != 6 {
		return Key{}, false
	}
	k := Key{SrcIP: net.ParseIP(parts[0]), DstIP: net.ParseIP(parts[1])}
	if k.SrcIP == nil || k.DstIP == nil {
		return Key{}, false
	}
	src, e1 := strconv.ParseUint(parts[2], 10, 16)
	dst, e2 := strconv.ParseUint(parts[3], 10, 16)
	proto, e3 := strconv.ParseUint(parts[4], 10, 8)
	dir, e4 := strconv.ParseUint(parts[5], 10, 8)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || dir > uint64(DirReverse) {
		return Key{}, false
	}
	k.SrcPort, k.DstPort, k.Proto, k.Dir = uint16(src), uint16(dst), uint8(proto), Direction(dir)
	return k, k.Hash() == id
}
