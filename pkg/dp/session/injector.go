// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

// Package session sends TCP resets for aborted sessions. It knows TCP
// tuples and sequence numbers, not policy.
package session

import (
	"errors"
	"net/netip"
)

// Reset describes one payload-free IPv4 RST. It is sent with source Src to
// Dst, so Src is spoofed as the peer of the endpoint being reset.
type Reset struct {
	Src, Dst netip.AddrPort
	Seq      uint32
}

// Injector sends TCP resets.
type Injector interface {
	// SendRST sends one payload-free IPv4 RST with route-selected egress.
	// nil means the socket accepted it, not that the endpoint closed.
	SendRST(r Reset) error
	Close() error
}

// ErrUnsupportedPlatform reports that raw RST injection is unavailable.
var ErrUnsupportedPlatform = errors.New("session: raw TCP reset injection is not supported on this platform")

// NewInjector opens the platform injector. Raw IPv4 injection is not
// implemented yet, so it returns ErrUnsupportedPlatform on every OS.
func NewInjector() (Injector, error) {
	return nil, ErrUnsupportedPlatform
}
