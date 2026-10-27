// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpgate

import (
	"net/netip"
	"time"

	"github.com/tonylturner/containd/pkg/common/avscan"
)

// maxTargetBytes bounds the request target recorded in an Event.
const maxTargetBytes = 512

// Event records one gate decision. Object events carry a Verdict: one per
// scanned or refused body and one per unsupported message. Connection
// events carry an empty Verdict and a non-empty Error: the gate could not
// serve the connection (unknown destination, upstream dial failure,
// recovered panic) and closed it.
type Event struct {
	Time time.Time
	// ID identifies the transaction; it matches avscan.Object.ID.
	ID string
	// Direction is Upload for request bodies and Download for response
	// bodies. Unsupported request heads are Upload, response heads
	// Download.
	Direction avscan.Direction
	Client    netip.AddrPort
	Server    netip.AddrPort
	ICS       bool
	// Method, Host and Target describe the request; Target is truncated
	// to maxTargetBytes. Status is the response status for Download.
	Method string
	Host   string
	Target string
	Status int
	// Size is the body length delivered or refused: the declared
	// Content-Length when known, else the bytes received.
	Size int64
	// SHA256 covers the held bytes. SHA256Partial is set when they are not
	// the whole object: oversized, disk-error or incomplete prefixes and
	// bodies streamed on after the hold, refused or passed alike. SHA256
	// is empty when nothing was held.
	SHA256        string
	SHA256Partial bool
	// Streamed is the body bytes forwarded to the client before the
	// decision; non-zero only for stream_tail downloads. A reset discards
	// what was still in transit, so the client may hold fewer.
	Streamed  int64
	Verdict   avscan.Verdict
	Reason    avscan.Reason
	Signature string
	Backend   string
	Detail    string
	Action    avscan.Action
	// Duration runs from the request head to the decision.
	Duration time.Duration
	// Error is set on connection events only.
	Error string
}

// boundTarget truncates t to maxTargetBytes.
func boundTarget(t string) string {
	if len(t) > maxTargetBytes {
		return t[:maxTargetBytes]
	}
	return t
}
