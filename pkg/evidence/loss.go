// SPDX-License-Identifier: Apache-2.0

package evidence

import "time"

// CollectionLoss retains the most precise exclusion available at collection.
// A connection ID excludes that entire incarnation. Otherwise both interval
// endpoints are inclusive capture times. Neither means dataset-wide loss.
type CollectionLoss struct {
	Code         string    `json:"code"`
	ConnectionID string    `json:"connectionId,omitempty"`
	Start        time.Time `json:"start,omitzero"`
	End          time.Time `json:"end,omitzero"`
}

// MaxLosses bounds per-dataset loss metadata and collector pending identities.
const MaxLosses = 1024

// Normalized makes map keys stable across JSON round trips and clock locations.
func (l CollectionLoss) Normalized() CollectionLoss {
	l.Start = l.Start.Round(0).UTC()
	l.End = l.End.Round(0).UTC()
	return l
}

// RecordLoss preserves legacy unlocalized gaps before adding new localization.
// A later localized loss must never narrow an earlier unknown loss of that code.
func (d *Dataset) RecordLoss(loss CollectionLoss) {
	loss = loss.Normalized()
	for _, prior := range d.Losses {
		if prior.Code == "collection_loss" && prior.ConnectionID == "" && prior.Start.IsZero() && prior.End.IsZero() {
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
	if !found && loss.Code != "outcome_loss" {
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

// LossTouches fails closed for legacy gaps or invalid/missing time authority.
// first/last span all retained observations of the connection, not just a
// candidate relation's references.
func (d Dataset) LossTouches(connection string, first, last time.Time) bool {
	for _, code := range d.Gaps {
		if code == "outcome_loss" {
			continue
		}
		localized := false
		for _, loss := range d.Losses {
			if loss.Code == "outcome_loss" {
				continue
			}
			localized = localized || loss.Code == code
		}
		if !localized {
			return true
		}
	}
	for _, loss := range d.Losses {
		if loss.Code == "outcome_loss" {
			continue
		}
		if loss.ConnectionID != "" {
			if loss.ConnectionID == connection {
				return true
			}
			continue
		}
		if loss.Start.IsZero() || loss.End.IsZero() || loss.End.Before(loss.Start) ||
			first.IsZero() || last.IsZero() || (!last.Before(loss.Start) && !first.After(loss.End)) {
			return true
		}
	}
	return false
}
