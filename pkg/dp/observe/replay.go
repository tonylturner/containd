// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"fmt"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/identify"
)

func (o *Observer) replay(key identify.Key, c *connection, r identify.Replay) []Batch {
	var out []Batch
	if c.meta.Transport == 17 {
		// Stamps and datagrams have identical arrival order, including empty UDP.
		if len(r.Datagrams) != len(c.stamps) {
			c.coverage = identify.Conflict
			o.endBinding(c)
			return []Batch{{Key: key, Err: fmt.Errorf("observation replay datagram attribution mismatch")}}
		}
		for i, dg := range r.Datagrams {
			if dg.Length != dg.Range.End-dg.Range.Start {
				c.coverage = identify.Truncated
				o.endBinding(c)
				out = append(out, Batch{Key: key, Dir: dg.Direction, At: c.stamps[i].at, State: c.stamps[i].state, Err: fmt.Errorf("observation replay contains a clipped datagram")})
				return out
			}
			out = append(out, o.decode(key, c, c.stamps[i], r.Bytes[dg.Direction][dg.Range.Start:dg.Range.End]))
		}
		return out
	}
	for _, s := range c.stamps {
		// Replay owns both contiguous and out-of-order ranges. Select only bytes
		// actually retained, never synthesize a gap or clip a missing suffix.
		segments := []identify.Segment{{Sequence: r.Sequence[s.dir], Bytes: r.Bytes[s.dir]}}
		segments = append(segments, r.Pending[s.dir]...)
		for _, seg := range segments {
			start := int(int32(s.seq - seg.Sequence))
			lo, hi := max(0, start), min(len(seg.Bytes), start+s.length)
			if lo >= hi {
				continue
			}
			part := s
			part.seq = seg.Sequence + uint32(lo)
			out = append(out, o.decode(key, c, part, seg.Bytes[lo:hi]))
		}
	}
	return out
}

func (o *Observer) decode(key identify.Key, c *connection, s stamp, data []byte) Batch {
	batch := Batch{Key: key, Dir: s.dir, State: s.state, At: s.at}
	pkt := &dpi.ParsedPacket{Payload: data, Proto: "udp", SrcPort: c.meta.Ports[s.dir], DstPort: c.meta.Ports[1-s.dir]}
	if c.meta.Transport == 6 {
		if !c.syn[s.dir] || c.roles[s.dir] == dpi.DirUnknown {
			c.coverage = identify.Midstream
			o.endBinding(c)
			batch.Err = fmt.Errorf("observation direction has no SYN coverage")
			return batch
		}
		pkt.Proto, pkt.Session, pkt.Dir, pkt.HasOffset = "tcp", c.session, c.roles[s.dir], true
		high := c.high[s.dir]
		pkt.Offset = high + int64(int32(s.seq-(c.base[s.dir]+uint32(high))))
		c.high[s.dir] = max(high, pkt.Offset+int64(len(data)))
	}
	result := o.opts.Manager.InspectProtocolAt(string(c.protocol), s.state, pkt, o.opts.Now())
	batch.Events, batch.Err = result.Events, result.Err
	for i := range batch.Events {
		ev := &batch.Events[i]
		if ev.Attributes == nil {
			ev.Attributes = make(map[string]any)
		}
		ev.Attributes[eventfields.KeyObservationOnly] = true
		ev.Attributes[eventfields.KeyBindingSource] = string(Observation)
		ev.Timestamp = s.at
	}
	return batch
}
