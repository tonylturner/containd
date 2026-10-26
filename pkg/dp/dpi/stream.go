// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package dpi

import (
	"fmt"
	"strconv"

	"github.com/tonylturner/containd/pkg/dp/flow"
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
}

// DecodedFrame is one complete frame at absolute range [Start,End).
type DecodedFrame struct {
	Start, End int64
	Events     []Event
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

// StreamErrKind classifies manager-side stream failures.
type StreamErrKind uint8

const (
	StreamOverflow StreamErrKind = iota + 1
	StreamOverlapConflict
	StreamOutOfOrderLimit
	// StreamUnverifiedRetransmission is a retransmission of consumed bytes
	// older than the history a verifying stream keeps.
	StreamUnverifiedRetransmission
	// StreamResync is a SYN with a new sequence number on a live stream
	// that fails closed.
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
}
