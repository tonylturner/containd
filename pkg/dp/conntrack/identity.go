// SPDX-License-Identifier: Apache-2.0

package conntrack

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
)

// Tuple is a TCP/UDP packet-space tuple. Family is AF_INET (2) or AF_INET6
// (10); interface policy zones are unrelated to conntrack zones.
type Tuple struct {
	Family, Protocol    uint8
	Source, Destination netip.AddrPort
}

func (t Tuple) Validate() error {
	s, d := t.Source.Addr(), t.Destination.Addr()
	if t.Protocol != 6 && t.Protocol != 17 {
		return fmt.Errorf("conntrack identity requires TCP/UDP")
	}
	if !s.IsValid() || !d.IsValid() || s.Zone() != "" || d.Zone() != "" ||
		s.Is4() != d.Is4() || s.Is4In6() || d.Is4In6() ||
		t.Family != 2 && t.Family != 10 || (t.Family == 2) != s.Is4() {
		return fmt.Errorf("conntrack identity has invalid address family")
	}
	return nil
}

// Evidence is an exact kernel record, not a public connection identifier.
// ID, optional Start and the engine epoch together guard incarnation reuse.
type Evidence struct {
	Original, Reply               Tuple
	Zone, OriginalZone, ReplyZone uint16
	ID, Status, TimeoutSeconds    uint32
	Start                         uint64
}

var (
	ErrUnsupportedZone = errors.New("conntrack identity: unsupported zone")
	ErrNotFound        = errors.New("conntrack identity: not found")
)

func (e Evidence) Validate(observed Tuple) error {
	if e.Zone != 0 || e.OriginalZone != 0 || e.ReplyZone != 0 {
		return ErrUnsupportedZone
	}
	if err := e.Original.Validate(); err != nil {
		return err
	}
	if err := e.Reply.Validate(); err != nil {
		return err
	}
	if e.TimeoutSeconds == 0 || e.Original.Family != e.Reply.Family ||
		e.Original.Protocol != e.Reply.Protocol || e.Original == e.Reply ||
		observed != e.Original && observed != e.Reply {
		return fmt.Errorf("conntrack identity has ambiguous or mismatched tuples")
	}
	return nil
}

// IdentityReader is owned by one resolver worker, including Close.
type IdentityReader interface {
	Lookup(context.Context, Tuple) (Evidence, error)
	Close() error
}
