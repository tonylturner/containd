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
	return flow.ICSServiceDirection(pkt.Proto, pkt.SrcPort, pkt.DstPort)
}

// wireServiceState is used before any connection evidence has been admitted.
func wireServiceState(pkt capture.Packet) flow.State {
	state := flow.State{Key: packetKey(pkt)}
	if dir, known := icsServiceDirection(pkt); known {
		state.Key.Dir = dir
	}
	if dir, known := handshakeDirection(pkt); known {
		state.Key.Dir = dir
	}
	return state
}
