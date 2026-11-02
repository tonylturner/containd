// SPDX-License-Identifier: Apache-2.0

package events

import (
	"github.com/tonylturner/containd/pkg/common/telemetry"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// Writer binds every publication to one immutable provenance.
type Writer struct {
	store  *Store
	origin telemetry.Origin
}

func (s *Store) Writer(origin telemetry.Origin) *Writer {
	return &Writer{store: s, origin: origin}
}

func (w *Writer) Store() *Store {
	if w == nil {
		return nil
	}
	return w.store
}

func (w *Writer) Origin() telemetry.Origin {
	if w == nil {
		return ""
	}
	return w.origin
}

func (w *Writer) Append(ev Event) Event {
	ev.Origin = w.origin
	return w.store.Append(ev)
}

func (w *Writer) Record(state *flow.State, pkt *dpi.ParsedPacket, in []dpi.Event) {
	w.store.record(state, pkt, in, w.origin)
}

func (w *Writer) MarkAborted(sessionID string) {
	w.store.markAborted(sessionID, w.origin)
}
