// SPDX-License-Identifier: Apache-2.0
package dnp3

import (
	"bytes"
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

// Inspection limits, not wire-format limits. No timers or background workers.
const (
	maxAssemblyBytes    = 64 * 1024
	maxAssemblySegments = 1024
	maxStationContexts  = 4096
	maxRetainedBytes    = 16 * 1024 * 1024
	contextCharge       = 1024
	assemblyIdle        = 30 * time.Second
	assemblyLifetime    = 60 * time.Second
)

type stationKey struct {
	session  string
	dir      dpi.StreamDir
	src, dst uint16
	master   bool
}

// LinkRange records physical provenance, never a fabricated contiguous frame.
type LinkRange struct {
	Start int64 `json:"start"`
	End   int64 `json:"end"`
}
type transportAssembly struct {
	data    []byte
	ranges  []LinkRange
	last    []byte
	seq     byte
	started time.Time
	badCRC  bool
}
type stationContext struct {
	requestSeq, requestFC byte
	requestValid          bool
	transport             *transportAssembly
	application           [2]applicationAssembly
	retry                 []byte
	fcb                   byte
	retryValid            bool
	touched               time.Time
}

// Decoder implements dpi.StreamDecoder and dpi.StreamEnder. A mutex also makes
// direct packet callers safe; no decoder state escapes ParseStream.
type Decoder struct {
	mu       sync.Mutex
	now      func() time.Time
	stations map[stationKey]*stationContext
	retained int
}

func NewDecoder() *Decoder { return NewDecoderWithClock(time.Now) }

// NewDecoderWithClock permits deterministic expiry tests. The clock must not
// call back into the decoder. nil selects time.Now.
func NewDecoderWithClock(now func() time.Time) *Decoder {
	if now == nil {
		now = time.Now
	}
	return &Decoder{now: now, stations: make(map[stationKey]*stationContext)}
}

func contextBytes(k stationKey, c *stationContext) int {
	n := contextCharge + len(k.session) + cap(c.retry)
	if a := c.transport; a != nil {
		n += cap(a.data) + cap(a.ranges)*16 + cap(a.last)
	}
	return n
}
func (d *Decoder) remove(k stationKey) {
	if c := d.stations[k]; c != nil {
		d.retained -= contextBytes(k, c)
		delete(d.stations, k)
	}
}
func (d *Decoder) prune(now time.Time) {
	for k, c := range d.stations {
		if now.Sub(c.touched) >= assemblyIdle {
			d.remove(k)
			continue
		}
		if a := c.transport; a != nil && now.Sub(a.started) >= assemblyLifetime {
			d.retained -= contextBytes(k, c)
			c.transport = nil
			d.retained += contextBytes(k, c)
		}
		for i := range c.application {
			a := &c.application[i]
			if now.Sub(a.started) >= assemblyLifetime || now.Sub(a.touched) >= assemblyIdle {
				*a = applicationAssembly{}
			}
		}
	}
}
func (d *Decoder) StreamEnded(session string, dir dpi.StreamDir) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for k := range d.stations {
		if k.session == session && k.dir == dir {
			d.remove(k)
		}
	}
}

func stationFor(v dpi.StreamView, f *DNP3Frame) stationKey {
	return stationKey{v.Session, v.Dir, f.Source, f.Destination, f.Control&ControlDIR != 0}
}
func (d *Decoder) assemble(st *flow.State, v dpi.StreamView, f *DNP3Frame, raw []byte, r LinkRange, now time.Time) []dpi.Event {
	k := stationFor(v, f)
	var codes, undecoded []string
	if f.badDataCRC {
		codes = append(codes, "dnp3.data_crc")
	}
	linkEvent := func() []dpi.Event {
		if len(codes)+len(undecoded) == 0 {
			return nil
		}
		ev := linkEvent(st, f, raw, codes, undecoded)
		return []dpi.Event{ev}
	}
	if len(f.Data) == 0 {
		// Primary reset-link-states resets only this station direction.
		if f.Control&ControlPRM != 0 && f.Control&15 == 0 {
			d.remove(k)
		}
		return linkEvent()
	}
	// Only primary confirmed/unconfirmed user data carries a transport header.
	if f.Control&ControlPRM == 0 || (f.Control&15 != 3 && f.Control&15 != 4) {
		undecoded = append(undecoded, "dnp3.link_payload")
		return linkEvent()
	}
	c := d.stations[k]
	if c == nil {
		charge := contextCharge + len(k.session)
		if len(d.stations) >= maxStationContexts || charge > maxRetainedBytes-d.retained {
			undecoded = append(undecoded, "dnp3.assembly_budget")
			return linkEvent()
		}
		c = &stationContext{}
		d.stations[k] = c
		d.retained += charge
	}
	before := contextBytes(k, c)
	defer func() { d.retained += contextBytes(k, c) - before }()
	c.touched = now
	// Only confirmed user-data with FCV has a retry identity. Identical new
	// unconfirmed FIR+FIN requests are legitimate and are never deduplicated.
	if f.Control&15 == 3 && f.Control&ControlFCV != 0 {
		fcb := f.Control & ControlFCB
		if c.retryValid && c.fcb == fcb {
			if bytes.Equal(c.retry, f.Data) {
				codes = append(codes, "dnp3.link_duplicate")
			} else {
				c.transport = nil
				codes = append(codes, "dnp3.link_retry_conflict")
				undecoded = append(undecoded, "dnp3.transport_incomplete")
			}
			return linkEvent()
		}
		if len(f.Data) > maxRetainedBytes-d.retained {
			undecoded = append(undecoded, "dnp3.assembly_budget")
			c.transport = nil
			return linkEvent()
		}
		c.retry = copyBytes(f.Data)
		c.fcb = fcb
		c.retryValid = true
	}
	h := f.Data[0]
	seq := h & 63
	fir, fin := h&TransportFIR != 0, h&TransportFIN != 0
	if a := c.transport; a != nil && seq == a.seq && bytes.Equal(a.last, f.Data) {
		codes = append(codes, "dnp3.transport_duplicate")
		return linkEvent()
	}
	if fir {
		if c.transport != nil {
			codes = append(codes, "dnp3.transport_restart")
			undecoded = append(undecoded, "dnp3.transport_incomplete")
		}
		c.transport = &transportAssembly{seq: seq, started: now}
	} else if c.transport == nil {
		codes = append(codes, "dnp3.transport_orphan")
		undecoded = append(undecoded, "dnp3.transport_incomplete")
		return linkEvent()
	} else {
		a := c.transport
		if seq == a.seq {
			c.transport = nil
			codes = append(codes, "dnp3.transport_conflict")
			undecoded = append(undecoded, "dnp3.transport_incomplete")
			return linkEvent()
		}
		if seq != (a.seq+1)&63 {
			c.transport = nil
			codes = append(codes, "dnp3.transport_sequence")
			undecoded = append(undecoded, "dnp3.transport_incomplete")
			return linkEvent()
		}
	}
	a := c.transport
	if len(a.data) > maxAssemblyBytes-(len(f.Data)-1) || len(a.ranges) >= maxAssemblySegments {
		c.transport = nil
		undecoded = append(undecoded, "dnp3.assembly_limit")
		return linkEvent()
	}
	// Reserve exact-size owned storage, accounting for provenance and retry
	// bytes before allocation. Bounds include empty segments and metadata.
	needed := len(a.data) + len(f.Data) - 1 + (len(a.ranges)+1)*16 + len(f.Data)
	available := maxRetainedBytes - (d.retained - before + contextBytes(k, c))
	old := cap(a.data) + cap(a.ranges)*16 + cap(a.last)
	if needed-old > available {
		c.transport = nil
		undecoded = append(undecoded, "dnp3.assembly_budget")
		return linkEvent()
	}
	data := make([]byte, len(a.data)+len(f.Data)-1)
	copy(data, a.data)
	copy(data[len(a.data):], f.Data[1:])
	a.data = data
	ranges := make([]LinkRange, len(a.ranges)+1)
	copy(ranges, a.ranges)
	ranges[len(a.ranges)] = r
	a.ranges = ranges
	a.last = copyBytes(f.Data)
	a.seq = seq
	a.badCRC = a.badCRC || f.badDataCRC
	if !fin {
		return linkEvent()
	}
	c.transport = nil
	if len(a.data) < 2 {
		codes = append(codes, "dnp3.application_header")
		undecoded = append(undecoded, "dnp3.application_incomplete")
		return linkEvent()
	}
	// Existing application helpers use a leading transport octet. This is an
	// owned logical payload, not a physical frame; raw_hex remains raw below.
	complete := *f
	complete.Data = append([]byte{TransportFIR | TransportFIN}, a.data...)
	complete.FunctionCode = a.data[1]
	complete.badDataCRC = a.badCRC
	events := frameEvents(st, &complete, raw)
	for i := range events {
		attrs := events[i].Attributes
		attrs["link_ranges"] = a.ranges
		attrs["transport_segments"] = len(a.ranges)
		attrs["stream_session"] = v.Session
		attrs["stream_direction"] = uint8(v.Dir)
		d.application(k, c, a.data, attrs, now)
		mergeCodes(attrs, eventfields.KeyConformance, codes)
		mergeCodes(attrs, eventfields.KeyUndecoded, undecoded)
	}
	return events
}
func mergeCodes(attrs map[string]any, key string, codes []string) {
	if len(codes) == 0 {
		return
	}
	prior, _ := eventfields.Strings(attrs, key)
	attrs[key] = sortedFindings(append(prior, codes...))
}
func linkEvent(st *flow.State, f *DNP3Frame, raw []byte, codes, undecoded []string) dpi.Event {
	attrs := map[string]any{"source_address": f.Source, "destination_address": f.Destination, eventfields.KeyDirection: linkDirection(f.Control), "raw_hex": rawHex(raw)}
	mergeCodes(attrs, eventfields.KeyConformance, codes)
	mergeCodes(attrs, eventfields.KeyUndecoded, undecoded)
	return dpi.Event{FlowID: flowID(st), Proto: eventfields.ProtoDNP3, Kind: "session", Attributes: attrs, Timestamp: time.Now().UTC()}
}

func copyBytes(b []byte) []byte {
	owned := make([]byte, len(b))
	copy(owned, b)
	return owned
}
