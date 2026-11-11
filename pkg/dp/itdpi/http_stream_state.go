// SPDX-License-Identifier: Apache-2.0

package itdpi

import (
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// Session IDs distinguish incarnations when the caller provides them. Legacy
// inspection has directional stream IDs; use the shared connection identity,
// or the unordered wire tuple when no connection tracker is available.
func metadataConnectionKey(st *flow.State, v dpi.StreamView) string {
	if v.Dir != dpi.DirUnknown {
		return "session/" + v.Session
	}
	if c := st.Connection.Load(); c != nil && c.Key != "" {
		return "connection/" + c.Key
	}
	k := st.Key
	k.Dir = flow.DirForward
	peer := k.Reversed()
	peer.Dir = flow.DirForward
	a, b := k.Hash(), peer.Hash()
	return "wire/" + min(a, b)
}

func metadataFrame(res *dpi.StreamResult, v dpi.StreamView, n int, events []dpi.Event) {
	if n == 0 {
		return
	}
	start := v.Base + int64(res.Consumed)
	res.Consumed += n
	res.Frames = append(res.Frames, dpi.DecodedFrame{Start: start, End: v.Base + int64(res.Consumed), Events: events})
}

// Passive metadata decoders retain a terminal state instead of returning a
// framing error: a legacy manager otherwise discards their state and retries
// the next packet as a new stream. Unknown pickups are not protocol errors.
func metadataStop(st *flow.State, v dpi.StreamView, res *dpi.StreamResult, anchored bool, proto, reason string, events []dpi.Event) {
	if anchored {
		events = append(events, dpi.Event{FlowID: st.ID(), Proto: proto, Kind: "malformed", Attributes: map[string]any{"error": reason}})
	}
	metadataFrame(res, v, len(v.Bytes)-res.Consumed, events)
}
