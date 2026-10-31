// SPDX-License-Identifier: Apache-2.0

package capture

import "net/netip"

// QueueMetadata is receive-time evidence from NFQUEUE, not a later conntrack
// lookup. Zero device indices and empty names explicitly mean unavailable.
// Names are the actual devices, not a subnet-derived zone.
type QueueMetadata struct {
	Hook           uint8
	HasHook        bool
	InDev, OutDev  uint32
	IngressDevice  string
	EgressDevice   string
	Conntrack      *QueueConntrack
	ConntrackError string
}

// QueueTuple retains missing endpoints as invalid AddrPorts. Port zero is a
// valid value when its attribute was present.
type QueueTuple struct {
	Source, Destination netip.AddrPort
	Protocol            uint8
	HasProtocol         bool
}

// QueueConntrack carries independently validated fields. DirectionKnown is
// false without valid NFQA_CT_INFO; absent marks are not evidence of mark zero.
type QueueConntrack struct {
	Mark, Status            uint32
	HasMark, HasStatus      bool
	Original, Reply         QueueTuple
	DirectionKnown, IsReply bool
}
