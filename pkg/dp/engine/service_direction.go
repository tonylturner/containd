// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package engine

import (
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// icsServiceDirection is a midstream hint only: observed handshakes and
// existing connection state take precedence, including on unusual ports.
func icsServiceDirection(pkt capture.Packet) (flow.Direction, bool) {
	known := func(port uint16) bool {
		switch pkt.Proto {
		case 6:
			switch port {
			case 502, 20000, 44818, 102, 4840, iec104Port:
				return true
			}
		case 17:
			return port == 2222 || port == 47808
		}
		return false
	}
	src, dst := known(pkt.SrcPort), known(pkt.DstPort)
	if src == dst {
		return flow.DirForward, false
	}
	if src {
		return flow.DirReverse, true
	}
	return flow.DirForward, true
}
