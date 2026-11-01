// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"net/netip"
	"time"
)

// LossScope identifies both directions of a wire tuple, or a host pair when
// Ports is false. It applies to every matching incarnation, without time bounds.
type LossScope struct {
	Source      Endpoint `json:"source"`
	Destination Endpoint `json:"destination"`
	Transport   string   `json:"transport"`
	Ports       bool     `json:"ports"`
}

// CollectionLoss retains the strongest available exclusion authority. Old time
// fields remain readable, but cannot prove any connection disjoint from loss.
type CollectionLoss struct {
	Code         string    `json:"code"`
	ConnectionID string    `json:"connectionId,omitempty"`
	Scope        LossScope `json:"scope,omitzero"`
	Start        time.Time `json:"start,omitzero"`
	End          time.Time `json:"end,omitzero"`
}

func nonExcludingLoss(code string) bool {
	return code == "outcome_loss" || code == "capture_unrelated"
}

// MaxLosses bounds per-dataset loss metadata and collector pending identities.
const MaxLosses = 1024

// Normalized makes map keys stable across JSON round trips and clock locations.
func (l CollectionLoss) Normalized() CollectionLoss {
	l.Start = l.Start.Round(0).UTC()
	l.End = l.End.Round(0).UTC()
	if !l.Scope.Ports {
		l.Scope.Source.Port, l.Scope.Destination.Port = 0, 0
	}
	for _, endpoint := range []*Endpoint{&l.Scope.Source, &l.Scope.Destination} {
		if ip, err := netip.ParseAddr(endpoint.IP); err == nil {
			endpoint.IP = ip.Unmap().String()
		}
	}
	a, b := l.Scope.Source, l.Scope.Destination
	if a.IP > b.IP || a.IP == b.IP && a.Port > b.Port {
		l.Scope.Source, l.Scope.Destination = b, a
	}
	return l
}

// RecordLoss preserves legacy unlocalized gaps before adding new localization.
// A later localized loss must never narrow an earlier unknown loss of that code.
func (d *Dataset) RecordLoss(loss CollectionLoss) {
	loss = loss.Normalized()
	for _, prior := range d.Losses {
		if prior.Code == "collection_loss" && prior.ConnectionID == "" && prior.Scope == (LossScope{}) && prior.Start.IsZero() && prior.End.IsZero() {
			return
		}
	}
	for _, code := range d.Gaps {
		found := false
		for _, prior := range d.Losses {
			found = found || prior.Code == code
		}
		if !found {
			d.Losses = append(d.Losses, CollectionLoss{Code: code})
		}
	}
	found := false
	for _, code := range d.Gaps {
		found = found || code == loss.Code
	}
	if !found && !nonExcludingLoss(loss.Code) {
		// Annotation loss is visible in losses/counters, not in the summary of
		// gaps that can invalidate certification inputs.
		d.Gaps = append(d.Gaps, loss.Code)
	}
	for _, prior := range d.Losses {
		if prior.Normalized() == loss {
			return
		}
	}
	if len(d.Losses) >= MaxLosses {
		// Once precision is exhausted, retain bounded, conservative authority.
		d.Losses = []CollectionLoss{{Code: "collection_loss"}}
		d.Gaps = []string{"collection_loss"}
		return
	}
	d.Losses = append(d.Losses, loss)
}

// LossTouches never infers lifecycle bounds from retained message timestamps.
// Missing/legacy scope fails closed; coordinates match either wire direction.
func (d Dataset) LossTouches(connection string, wire Tuple) bool {
	for _, code := range d.Gaps {
		if nonExcludingLoss(code) {
			continue
		}
		localized := false
		for _, loss := range d.Losses {
			localized = localized || loss.Code == code
		}
		if !localized {
			return true
		}
	}
	for _, loss := range d.Losses {
		if nonExcludingLoss(loss.Code) {
			continue
		}
		if loss.ConnectionID != "" {
			if loss.ConnectionID == connection {
				return true
			}
			continue
		}
		s := loss.Scope
		if !validIP(s.Source.IP) || !validIP(s.Destination.IP) || (s.Transport != "tcp" && s.Transport != "udp") {
			return true
		}
		if !validIP(wire.Source.IP) || !validIP(wire.Destination.IP) || wire.Transport == "" {
			return true
		}
		if s.Transport != wire.Transport {
			continue
		}
		match := func(a, b Endpoint) bool {
			x, _ := netip.ParseAddr(a.IP)
			y, _ := netip.ParseAddr(b.IP)
			return x.Unmap() == y.Unmap() && (!s.Ports || a.Port == b.Port)
		}
		if match(s.Source, wire.Source) && match(s.Destination, wire.Destination) || match(s.Source, wire.Destination) && match(s.Destination, wire.Source) {
			return true
		}
	}
	return false
}
func validIP(s string) bool { _, err := netip.ParseAddr(s); return err == nil }
