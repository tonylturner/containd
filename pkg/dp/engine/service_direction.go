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
