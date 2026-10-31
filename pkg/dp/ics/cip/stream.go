// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package cip

import (
	"encoding/hex"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

var _ dpi.StreamDecoder = (*Decoder)(nil)

func (d *Decoder) Protocol() string { return eventfields.ProtoCIP }

// ParseStream emits one frame per EtherNet/IP encapsulation. Unknown commands
// still frame by length and retain their session events; only a length beyond
// the reassembly bound fails framing. UDP continues to use OnPacket.
func (d *Decoder) ParseStream(state *flow.State, v dpi.StreamView) (dpi.StreamResult, error) {
	var res dpi.StreamResult
	for res.Consumed < len(v.Bytes) {
		pos := res.Consumed
		hdr, err := frameEncapsulation(v.Bytes[pos:])
		if err != nil {
			return res, &dpi.FrameError{
				Offset: v.Base + int64(pos),
				Reason: err.Error(),
				Event:  malformedEvent(state, v.Bytes[pos:], err),
			}
		}
		if hdr == nil {
			res.NeedMore = true
			break
		}
		end := pos + eipHeaderSize + int(hdr.Length)
		res.Frames = append(res.Frames, dpi.DecodedFrame{
			Start:  v.Base + int64(pos),
			End:    v.Base + int64(end),
			Events: encapsulationEvents(state, hdr),
		})
		res.Consumed = end
	}
	return res, nil
}

func malformedEvent(state *flow.State, data []byte, err error) dpi.Event {
	const maxRawHex = 512
	id := ""
	if state != nil {
		id = state.ID()
	}
	return dpi.Event{
		FlowID: id,
		Proto:  eventfields.ProtoCIP,
		Kind:   eventfields.KindMalformed,
		Attributes: map[string]any{
			eventfields.KeyError: err.Error(),
			"raw_hex":            hex.EncodeToString(data[:min(len(data), maxRawHex)]),
		},
	}
}
