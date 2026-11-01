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

// RecordLoss preserves legacy unlocalized gaps before adding new localization.
// A later localized loss must never narrow an earlier unknown loss of that code.
func (d *Dataset) RecordLoss(loss CollectionLoss) {
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
	if !found {
		d.Gaps = append(d.Gaps, loss.Code)
	}
	for _, prior := range d.Losses {
		if prior == loss {
			return
		}
	}
	d.Losses = append(d.Losses, loss)
}

// LossTouches fails closed for legacy gaps or invalid/missing time authority.
// first/last span all retained observations of the connection, not just a
// candidate relation's references.
func (d Dataset) LossTouches(connection string, first, last time.Time) bool {
	for _, code := range d.Gaps {
		localized := false
		for _, loss := range d.Losses {
			localized = localized || loss.Code == code
		}
		if !localized {
			return true
		}
	}
	for _, loss := range d.Losses {
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
