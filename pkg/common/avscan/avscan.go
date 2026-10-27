// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

// Package avscan is the contract between the HTTP object gate, which holds a
// complete transferred object, and the scanner backends (clamd INSTREAM and
// ICAP). It holds types and the pass/block decision only.
package avscan

import (
	"context"
	"io"
	"net/netip"
)

// Direction names which HTTP message carries the object.
type Direction string

const (
	// Upload is an HTTP request body (client to server; ICAP REQMOD).
	Upload Direction = "upload"
	// Download is an HTTP response body (server to client; ICAP RESPMOD).
	Download Direction = "download"
)

// Object is one complete HTTP message body held by the gate. The gate owns
// Body for the duration of Scan and releases it afterwards.
type Object struct {
	// ID identifies the transaction in events and logs.
	ID        string
	Direction Direction
	// Client is the connection opener; Server is the original destination.
	Client netip.AddrPort
	Server netip.AddrPort
	// RequestHead is the HTTP/1.x request line and header fields as they
	// will be sent upstream, ending with the blank line. Always set.
	RequestHead []byte
	// ResponseHead is the status line and header fields, ending with the
	// blank line. Set for Download only.
	ResponseHead []byte
	// Body is the message body after transfer decoding (chunked framing
	// removed) and before content decoding (gzip stays as sent). Size is
	// its exact length.
	Body io.ReaderAt
	Size int64
	// SHA256 is the lowercase hex SHA-256 of Body, computed while spooling.
	SHA256 string
	// ICS is true when Client or Server lies in an operator-marked ICS zone
	// or asset range.
	ICS bool
}

// Verdict is the scan outcome.
type Verdict string

const (
	Clean    Verdict = "clean"
	Infected Verdict = "infected"
	// Unscanned means no backend verdict exists; Reason says why. It is
	// never reported as clean.
	Unscanned Verdict = "unscanned"
)

// Reason explains an Unscanned verdict.
type Reason string

const (
	ReasonScannerError Reason = "scanner_error"
	ReasonTimeout      Reason = "timeout"
	ReasonOversized    Reason = "oversized"
	ReasonUnsupported  Reason = "unsupported"
	ReasonNotReady     Reason = "not_ready"
	// ReasonBusy means the gate's spool or concurrency limit was reached.
	ReasonBusy Reason = "busy"
	// ReasonAborted means the gate ended the transaction itself before a
	// verdict (client gone, Shutdown). It is recorded only; it never
	// reaches Decide and the object is never delivered.
	ReasonAborted Reason = "aborted"
)

// Result is a scanner backend's answer for one Object.
type Result struct {
	Verdict Verdict
	Reason  Reason // set when Verdict is Unscanned
	// Signature is the detection name when Verdict is Infected.
	Signature string
	// Backend names the scanner (for example "clamav" or "icap|host:port|service");
	// "gate" when the gate decided without a backend (busy, oversized,
	// not ready, unsupported).
	Backend string
	// Detail is a human-readable error or note; never a verdict.
	Detail string
}

// Scanner scans complete objects. Implementations are safe for concurrent
// use. Scan must honour ctx, must not touch Body after it returns, and must
// never report Clean for bytes it did not receive in full or for an answer it
// cannot positively classify (that is Unscanned). Results carry a verdict
// only: a backend never returns adapted content. Ready must return promptly.
type Scanner interface {
	Scan(ctx context.Context, obj Object) Result
	// Ready reports whether the backend can scan now, with a reason when not.
	Ready() (bool, string)
}

// FailPolicy is the configured treatment of Unscanned objects.
type FailPolicy string

const (
	FailOpen   FailPolicy = "open"
	FailClosed FailPolicy = "closed"
)

// Action is what the gate does with the held object.
type Action string

const (
	Deliver Action = "deliver"
	Block   Action = "block"
	// PassUnscanned delivers the object and records that it was not scanned.
	PassUnscanned Action = "pass_unscanned"
)

// Decide maps a result to an action. Infected is always blocked, ICS
// included. Any other non-clean result is unscanned: it passes only under
// FailOpen, or for ICS objects when icsBypass is set. An empty or unknown
// policy is treated as FailClosed.
func Decide(r Result, policy FailPolicy, ics, icsBypass bool) Action {
	switch r.Verdict {
	case Clean:
		return Deliver
	case Infected:
		return Block
	}
	if policy == FailOpen || (ics && icsBypass) {
		return PassUnscanned
	}
	return Block
}
