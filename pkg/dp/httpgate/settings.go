// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package httpgate

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"os"
	"time"

	"github.com/tonylturner/containd/pkg/common/avscan"
)

// Settings is one validated gate configuration. Every transaction uses the
// snapshot that was current when its request head was parsed.
type Settings struct {
	// ScanUploads selects request bodies; ScanDownloads selects response
	// bodies. An unselected body is relayed with its original framing.
	ScanUploads   bool
	ScanDownloads bool
	// MaxObjectBytes is the largest body the gate holds. A longer body is
	// Unscanned/oversized and follows FailPolicy.
	MaxObjectBytes int64
	// FailPolicy is the treatment of every Unscanned result.
	FailPolicy avscan.FailPolicy
	// ICSBypass passes Unscanned objects between ICS endpoints regardless
	// of FailPolicy. Infected objects are blocked either way.
	ICSBypass bool
	// IsICS reports whether either endpoint is an operator-marked ICS
	// zone or asset. nil marks nothing as ICS.
	IsICS func(client, server netip.Addr) bool
	// SpoolDir receives the exclusive, immediately unlinked temporary
	// files of bodies longer than MemoryThreshold. Empty means the
	// operating system's temporary directory.
	SpoolDir string
	// MemoryThreshold is the largest body held entirely in memory.
	MemoryThreshold int64
	// MaxConnections bounds the client connections served concurrently,
	// refusal drains included; a connection accepted over the limit is
	// closed at once and reported at a bounded rate.
	MaxConnections int
	// MaxConcurrentObjects bounds the bodies held at once. Memory stays
	// below MaxConcurrentObjects × MemoryThreshold and disk below
	// MaxConcurrentObjects × MaxObjectBytes.
	MaxConcurrentObjects int
	// IdleTimeout bounds every single read or write on either connection.
	IdleTimeout time.Duration
	// ObjectTimeout bounds the receipt of one head or body from its first
	// byte.
	ObjectTimeout time.Duration
	// DialTimeout bounds the upstream connection attempt.
	DialTimeout time.Duration
	// ScanTimeout bounds one Scanner.Scan call.
	ScanTimeout time.Duration
}

// validate reports the first problem with s and fills defaults.
func (s *Settings) validate() error {
	switch s.FailPolicy {
	case avscan.FailOpen, avscan.FailClosed:
	default:
		return fmt.Errorf("httpgate: fail policy %q is neither open nor closed", s.FailPolicy)
	}
	for _, l := range []struct {
		name  string
		value int64
	}{
		{"MaxObjectBytes", s.MaxObjectBytes},
		{"MemoryThreshold", s.MemoryThreshold},
		{"MaxConnections", int64(s.MaxConnections)},
		{"MaxConcurrentObjects", int64(s.MaxConcurrentObjects)},
		{"IdleTimeout", int64(s.IdleTimeout)},
		{"ObjectTimeout", int64(s.ObjectTimeout)},
		{"DialTimeout", int64(s.DialTimeout)},
		{"ScanTimeout", int64(s.ScanTimeout)},
	} {
		if l.value <= 0 {
			return fmt.Errorf("httpgate: %s must be positive, got %d", l.name, l.value)
		}
	}
	objects := int64(s.MaxConcurrentObjects)
	if s.MaxObjectBytes > math.MaxInt64/objects {
		return errors.New("httpgate: MaxConcurrentObjects × MaxObjectBytes overflows")
	}
	if s.MemoryThreshold > math.MaxInt64/objects {
		return errors.New("httpgate: MaxConcurrentObjects × MemoryThreshold overflows")
	}
	if s.SpoolDir == "" {
		s.SpoolDir = os.TempDir()
	}
	return nil
}

// ics evaluates IsICS for one connection.
func (s *Settings) ics(client, server netip.AddrPort) bool {
	return s.IsICS != nil && s.IsICS(client.Addr(), server.Addr())
}

// decide applies the configured policy to r.
func (s *Settings) decide(r avscan.Result, ics bool) avscan.Action {
	return avscan.Decide(r, s.FailPolicy, ics, s.ICSBypass)
}
