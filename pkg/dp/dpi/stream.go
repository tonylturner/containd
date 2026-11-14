// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package dpi

import (
	"fmt"
	"strconv"

	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/limits"
)

// StreamDir is the direction of one TCP byte stream within a session.
type StreamDir uint8

const (
	DirUnknown StreamDir = iota
	ClientToServer
	ServerToClient
)

// StreamView is the contiguous byte range the manager holds for one stream
// direction. It is read-only and valid only during ParseStream.
type StreamView struct {
	// Session is the incarnation ID or, for legacy streams, the directional
	// flow hash.
	Session string
	Dir     StreamDir
	Base    int64 // absolute offset of Bytes[0]
	Bytes   []byte
	// PacketStart locates the current payload in Bytes, only when the entire
	// segment extends the contiguous stream in order (not a replay or a hole).
	PacketStart    int
	HasPacketStart bool
	// Role is transport authority, independent of Dir and stream identity.
	// DirUnknown means that the connection initiator is not known.
	Role StreamDir
	// Enforcing is the effective scope of the session that owns allocations.
	// An owner captures it at admission; retained storage never changes class.
	Enforcing bool
}

// DecodedFrame is one complete frame at absolute range [Start,End).
type DecodedFrame struct {
	Start, End int64
	Events     []Event
	// Coverage names the complete logical unit's exact carrying ranges in this
	// direction. Nil means [Start,End), except Pending authorizes no bytes.
	Coverage []CoverageRange
	// Pending is a physical DNP3 data frame with no completed application fragment.
	Pending bool
	// Unit is immutable decoder-validated protocol data, never event attributes.
	Unit ParsedUnit
}

// StreamResult is a framed decoder's parse of one StreamView.
type StreamResult struct {
	Frames   []DecodedFrame // contiguous from Base, in order
	Consumed int            // Frames[last].End - Base, or 0
	NeedMore bool           // incomplete tail; not an error
}

// FrameError reports a stream that cannot be framed at Offset. Nothing at
// or after Offset is parsed.
type FrameError struct {
	Offset int64 // absolute start of the frame that cannot be framed
	Reason string
	Event  Event // its single malformed event
}

func (e *FrameError) Error() string {
	return "dpi: cannot frame stream at offset " + strconv.FormatInt(e.Offset, 10) + ": " + e.Reason
}

// StreamDecoder is a Decoder that frames a TCP byte stream itself. On TCP
// the manager calls ParseStream, never OnPacket, and only a StreamDecoder
// trims the stream buffer. Decoders keep no reference to v.Bytes.
type StreamDecoder interface {
	Decoder
	Protocol() string // event Proto, e.g. "iec104", "modbus", "dnp3"
	ParseStream(state *flow.State, v StreamView) (StreamResult, error)
}

// StreamEnder is an optional StreamDecoder extension for decoders that keep
// state per stream across ParseStream calls. The manager calls StreamEnded
// once each time it discards the state of one stream (end, close, reset,
// failure, replacement or idle expiry), serialized with ParseStream. The
// decoder drops its state for that stream and must not call the manager.
type StreamEnder interface {
	StreamEnded(session string, dir StreamDir)
}

// StreamResynchronizer is a passive decoder's recovery policy for reassembly
// loss. Outside fail-closed inspection the manager drops held bytes but retains
// decoder lifetime and transport position. The decoder enters resynchronization
// and owns any bounded diagnostic events; the loss is not a fatal Inspect error.
// Decoders without this extension retain the strict stream failure contract.
type StreamResynchronizer interface {
	ResyncStream(state *flow.State, v StreamView, cause *StreamError) []Event
}

// StreamErrKind classifies manager-side stream failures.
type StreamErrKind uint8

const (
	StreamOverflow StreamErrKind = iota + 1
	StreamOverlapConflict
	StreamOutOfOrderLimit
	// StreamUnverifiedRetransmission is a retransmission of consumed bytes
	// older than the history a verifying stream keeps.
	StreamUnverifiedRetransmission
	// StreamResync is the payload of a SYN that does not anchor the stream
	// it belongs to, which fails closed: the payload's place in the stream
	// is unknown.
	StreamResync
	// StreamDecoderPanic is a stream whose framing decoder panicked
	// (Manager.FailStream).
	StreamDecoderPanic
	// StreamMidStream is a stream that fails closed but was picked up
	// mid-connection: it began without an observed SYN (the flow was first
	// seen after its handshake, or ended and was seen again), or the idle
	// sweep dropped its partial frame. Its bytes need not start a frame.
	StreamMidStream
	// StreamDenied is a stream that fails closed whose connection the
	// policy denied (Manager.FailStream). The denied bytes were consumed,
	// so a retransmission of them would otherwise pass as a duplicate.
	StreamDenied
	// StreamNonAdmit has consumed a decoded message that did not admit
	// its packet. Retries must retain the non-admitting continuation,
	// rather than passing as already-inspected duplicate bytes.
	StreamNonAdmit
	// StreamStateLimit is a refused retained inspection allocation.
	StreamStateLimit
)

func (k StreamErrKind) String() string {
	switch k {
	case StreamOverflow:
		return "overflow"
	case StreamOverlapConflict:
		return "overlap_conflict"
	case StreamOutOfOrderLimit:
		return "out_of_order_limit"
	case StreamUnverifiedRetransmission:
		return "unverified_retransmission"
	case StreamResync:
		return "resync"
	case StreamDecoderPanic:
		return "decoder_panic"
	case StreamMidStream:
		return "midstream"
	case StreamDenied:
		return "denied"
	case StreamNonAdmit:
		return "non_admit"
	case StreamStateLimit:
		return "state_limit"
	default:
		return "unknown(" + strconv.Itoa(int(k)) + ")"
	}
}

// StreamError is a manager-side stream failure (buffer bounds, overlap).
type StreamError struct {
	Kind   StreamErrKind
	Offset int64
	Proto  string
}

// StateLimitError records a single allocation-refusal transition. Callers keep
// the returned failure in already-admitted metadata until the stream ends.
func StateLimitError(r limits.Resources, enforcing bool, proto string, offset int64) *StreamError {
	mode := limits.ModeMonitor
	if enforcing {
		mode = limits.ModeEnforce
	}
	r.Ledger.Record(limits.TableInspection, limits.ReasonRefused, mode)
	return &StreamError{Kind: StreamStateLimit, Proto: proto, Offset: offset}
}

func (e *StreamError) Error() string {
	return fmt.Sprintf("dpi: %s stream %s at offset %d", e.Proto, e.Kind, e.Offset)
}

// InspectResult is the full outcome of Manager.Inspect for one packet.
type InspectResult struct {
	Proto    string         // framed decoder's Protocol(), "" if none
	Events   []Event        // all events, each once; the error's malformed event last
	Frames   []DecodedFrame // framed decoder only, absolute ranges
	Framed   bool           // a StreamDecoder handled this direction
	NeedMore bool
	Gap      bool // bytes buffered beyond a hole; nothing after it parsed
	// Err is the framed decoder's *FrameError or a *StreamError. A legacy
	// decoder's OnPacket error passes through unchanged, as OnPacket did.
	Err error
	// Failed reports a stream that had failed before this packet: Err is
	// the error it failed with, and nothing was inspected.
	Failed bool
}
