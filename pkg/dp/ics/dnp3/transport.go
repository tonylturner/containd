// SPDX-License-Identifier: Apache-2.0
package dnp3

import (
	"bytes"
	"fmt"
	"sync"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/limits"
)

// Inspection limits, not wire-format limits. No timers or background workers.
const (
	maxAssemblyBytes    = 64 * 1024
	maxAssemblySegments = 1024
	maxStationContexts  = 4096
	maxRetainedBytes    = 16 * 1024 * 1024
	contextCharge       = int(limits.DNP3StationMetadataBytes)
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

// transportRange preserves retries for authorization without changing the
// historical event projection's logical segment count and ranges.
type transportRange struct {
	LinkRange
	retry bool
}

const transportRangeBytes = 24

type transportAssembly struct {
	data                   []byte
	ranges                 []transportRange
	last                   []byte
	seq                    byte
	started                time.Time
	badCRC, badCoverageCRC bool
	confirmed, invalid     bool
}
type stationContext struct {
	class                 limits.Class
	failure               *dpi.StreamError
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
	mu        sync.Mutex
	now       func() time.Time
	stations  map[stationKey]*stationContext
	resources limits.Resources
	leases    [2]*limits.Lease
}

func NewDecoder() *Decoder { return NewDecoderWithClock(time.Now) }

// NewDecoderWithClock permits deterministic expiry tests. The clock must not
// call back into the decoder. nil selects time.Now.
func NewDecoderWithClock(now func() time.Time) *Decoder {
	if now == nil {
		now = time.Now
	}
	return &Decoder{now: now, stations: make(map[stationKey]*stationContext), resources: limits.NewResources(nil, nil)}
}

func contextBytes(k stationKey, c *stationContext) int {
	n := contextCharge + len(k.session) + cap(c.retry)
	if a := c.transport; a != nil {
		n += cap(a.data) + cap(a.ranges)*transportRangeBytes + cap(a.last)
	}
	return n
}
func (d *Decoder) remove(k stationKey) {
	if c := d.stations[k]; c != nil {
		charge := contextBytes(k, c)
		delete(d.stations, k)
		c.retry, c.transport = nil, nil
		d.refund(c.class, charge)
	}
}
func (d *Decoder) prune(now time.Time) {
	for k, c := range d.stations {
		if now.Sub(c.touched) >= assemblyIdle {
			d.remove(k)
			continue
		}
		if a := c.transport; a != nil && now.Sub(a.started) >= assemblyLifetime {
			old := contextBytes(k, c)
			c.transport = nil
			d.refund(c.class, old-contextBytes(k, c))
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
func (d *Decoder) assemble(st *flow.State, v dpi.StreamView, f *DNP3Frame, raw []byte, r LinkRange, now time.Time, decoded *dpi.DecodedFrame) ([]dpi.Event, error) {
	k := stationFor(v, f)
	u := linkUnit(f)
	decoded.Unit = u
	if len(f.Data) > 0 {
		u.LinkOnly = false
	}
	var codes, undecoded []string
	var pending bool
	if f.badDataCRC {
		codes = append(codes, "dnp3.data_crc")
	}
	linkEvent := func() ([]dpi.Event, error) {
		if len(codes)+len(undecoded) > 0 || len(f.Data) > 0 {
			u.shapeErr = fmt.Errorf("%w: %v %v", ErrUnsupportedShape, codes, undecoded)
		}
		if pending {
			decoded.Unit = nil
			decoded.Pending = true
		}
		if len(codes)+len(undecoded) == 0 {
			return nil, nil
		}
		ev := linkEvent(st, f, raw, codes, undecoded)
		return []dpi.Event{ev}, nil
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
		if len(d.stations) >= maxStationContexts {
			undecoded = append(undecoded, "dnp3.assembly_budget")
			return linkEvent()
		}
		class := limits.ClassObserve
		if v.Enforcing {
			class = limits.ClassEnforce
		}
		local, global := d.reserve(class, charge)
		if !local {
			undecoded = append(undecoded, "dnp3.assembly_budget")
			return linkEvent()
		}
		if !global {
			return nil, dpi.StateLimitError(d.resources, v.Enforcing, "dnp3", v.Base)
		}
		c = &stationContext{class: class}
		d.stations[k] = c
	}
	if c.failure != nil {
		return nil, c.failure
	}
	before := contextBytes(k, c)
	reserved := before
	defer func() { d.refund(c.class, reserved-contextBytes(k, c)) }()
	c.touched = now
	if a := c.transport; a != nil {
		a.badCoverageCRC = a.badCoverageCRC || f.badDataCRC
		if a.confirmed != u.Link.Confirmed {
			a.invalid = true
		}
	}
	// Only confirmed user-data with FCV has a retry identity. Identical new
	// unconfirmed FIR+FIN requests are legitimate and are never deduplicated.
	if f.Control&15 == 3 && f.Control&ControlFCV != 0 {
		fcb := f.Control & ControlFCB
		if c.retryValid && c.fcb == fcb {
			if bytes.Equal(c.retry, f.Data) {
				codes = append(codes, "dnp3.link_duplicate")
				if err := d.retainRetryRange(c, v, r, &reserved); err != nil {
					return nil, err
				}
			} else {
				c.transport = nil
				codes = append(codes, "dnp3.link_retry_conflict")
				undecoded = append(undecoded, "dnp3.transport_incomplete")
			}
			return linkEvent()
		}
		local, global := d.reserve(c.class, len(f.Data))
		if !local {
			undecoded = append(undecoded, "dnp3.assembly_budget")
			c.transport = nil
			return linkEvent()
		}
		if !global {
			return nil, d.budgetFailure(c, v)
		}
		reserved += len(f.Data)
		c.retry = copyBytes(f.Data)
		c.fcb = fcb
		c.retryValid = true
	}
	h := f.Data[0]
	seq := h & 63
	fir, fin := h&TransportFIR != 0, h&TransportFIN != 0
	if a := c.transport; a != nil && seq == a.seq && bytes.Equal(a.last, f.Data) {
		codes = append(codes, "dnp3.transport_duplicate")
		if err := d.retainRetryRange(c, v, r, &reserved); err != nil {
			return nil, err
		}
		return linkEvent()
	}
	if fir {
		if c.transport != nil {
			codes = append(codes, "dnp3.transport_restart")
			undecoded = append(undecoded, "dnp3.transport_incomplete")
		}
		c.transport = &transportAssembly{seq: seq, started: now, confirmed: u.Link.Confirmed, invalid: len(undecoded) > 0}
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
	needed := len(a.data) + len(f.Data) - 1 + (len(a.ranges)+1)*transportRangeBytes + len(f.Data)
	local, global := d.reserve(c.class, needed)
	if !local {
		c.transport = nil
		undecoded = append(undecoded, "dnp3.assembly_budget")
		return linkEvent()
	}
	if !global {
		return nil, d.budgetFailure(c, v)
	}
	reserved += needed
	data := make([]byte, len(a.data)+len(f.Data)-1)
	copy(data, a.data)
	copy(data[len(a.data):], f.Data[1:])
	a.data = data
	ranges := make([]transportRange, len(a.ranges)+1)
	copy(ranges, a.ranges)
	ranges[len(a.ranges)] = transportRange{LinkRange: r}
	a.ranges = ranges
	a.last = copyBytes(f.Data)
	a.seq = seq
	a.badCRC = a.badCRC || f.badDataCRC
	if !fin {
		pending = len(codes)+len(undecoded) == 0 && !a.invalid && !a.confirmed && !a.badCRC && !a.badCoverageCRC
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
	unitFrame := complete
	unitFrame.badDataCRC = a.badCRC || a.badCoverageCRC
	decoded.Unit = decodeUnit(&unitFrame)
	unit := decoded.Unit.(*Unit)
	if a.invalid {
		unit.shapeErr = fmt.Errorf("%w: inconsistent/restarted transport", ErrInvalidShape)
	}
	decoded.Coverage = make([]dpi.CoverageRange, len(a.ranges))
	for i, r := range a.ranges {
		decoded.Coverage[i] = dpi.CoverageRange{Start: r.Start, End: r.End}
	}
	if err := dpi.ValidateDecodedFrame(*decoded); err != nil {
		return nil, &dpi.FrameError{Offset: r.Start, Reason: err.Error(), Event: malformedEvent(st, raw, err)}
	}
	events := frameEvents(st, &complete, raw)
	for i := range events {
		attrs := events[i].Attributes
		// Events have a separate, bounded lifetime from retained decoder state.
		// Do not export the backing allocation charged to this assembly.
		eventRanges := make([]LinkRange, 0, len(a.ranges))
		for _, r := range a.ranges {
			if !r.retry {
				eventRanges = append(eventRanges, r.LinkRange)
			}
		}
		attrs["link_ranges"] = eventRanges
		attrs["transport_segments"] = len(eventRanges)
		attrs["stream_session"] = v.Session
		attrs["stream_direction"] = uint8(v.Dir)
		if err := d.application(k, c, a.data, attrs, now); err != nil && unit.shapeErr == nil {
			unit.shapeErr = err
		}
		mergeCodes(attrs, eventfields.KeyConformance, codes)
		mergeCodes(attrs, eventfields.KeyUndecoded, undecoded)
	}
	return events, nil
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
	return dpi.Event{FlowID: flowID(st), Proto: eventfields.ProtoDNP3, Kind: "session", Attributes: attrs}
}

func copyBytes(b []byte) []byte {
	owned := make([]byte, len(b))
	copy(owned, b)
	return owned
}
