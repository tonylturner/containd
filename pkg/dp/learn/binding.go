// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"context"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/evidence"
)

// Observation bindings cannot establish policy role authority. RoleEvidence
// retains that source on both passive parents and undecoded identification
// records, without changing the evidence envelope or discarding decoded data.
const observationBindingAuthority = "observation_binding"

// PortDecoderAuthority identifies role evidence from an adapter that retains
// connection binding and loss exclusions. Historical authorities without the
// corrected loss scope must be reimported or recollected, not trusted.
const PortDecoderAuthority = "port_decoder_and_nat_alias_loss_scope"

// WithheldObservationBinding excludes all parents on an observation binding.
const WithheldObservationBinding evidence.WithheldReason = "observation_binding"

const observationBindingLimit = "Observation-bound connections are excluded, including port-decoded parents emitted before content confirmation."

func observationBoundEvent(ev dpi.Event) bool {
	if ev.Proto == eventfields.ProtoIdentify && ev.Kind == eventfields.KindIdentification {
		state, _ := eventfields.String(ev.Attributes, eventfields.KeyIdentificationState)
		binding, _ := eventfields.String(ev.Attributes, eventfields.KeyBinding)
		mismatch, _ := eventfields.Bool(ev.Attributes, eventfields.KeyMismatch)
		return state == "confirmed" && (binding == "observation" || mismatch)
	}
	observationOnly, _ := eventfields.Bool(ev.Attributes, eventfields.KeyObservationOnly)
	binding, _ := eventfields.String(ev.Attributes, eventfields.KeyBindingSource)
	return observationOnly || binding == "observation"
}

func connectionExclusion(o evidence.Observation) evidence.WithheldReason {
	switch o.Authority.RoleEvidence {
	case observationBindingAuthority:
		return WithheldObservationBinding
	case PortDecoderAuthority:
		return ""
	default:
		return evidence.WithheldMissingAuthority
	}
}

// Scan the entire sealed dataset before grouping any relations. The decision
// belongs to the connection incarnation, not a protocol, direction, page or
// message timestamp; confirmation may follow every usable legacy parent.
func connectionExclusions(ctx context.Context, store evidence.Store, dataset evidence.Dataset) (map[string]evidence.WithheldReason, error) {
	excluded := map[string]evidence.WithheldReason{}
	cursor := ""
	for {
		page, err := store.ListObservations(ctx, dataset.ID, evidence.PageRequest{Limit: 200, Cursor: cursor})
		if err != nil {
			return nil, err
		}
		for _, o := range page.Items {
			recordConnectionExclusion(excluded, o)
			recordLossExclusion(dataset, excluded, o)
		}
		cursor = page.NextCursor
		if cursor == "" {
			return excluded, nil
		}
	}
}

func recordLossExclusion(ds evidence.Dataset, excluded map[string]evidence.WithheldReason, o evidence.Observation) {
	if ds.LossTouches(o) {
		excluded[o.ConnectionID] = evidence.WithheldCollectionLoss
	}
}

func recordConnectionExclusion(excluded map[string]evidence.WithheldReason, o evidence.Observation) {
	if excluded[o.ConnectionID] == evidence.WithheldCollectionLoss {
		return
	}
	reason := connectionExclusion(o)
	// A known observation binding is more specific than missing authority.
	if reason != "" && excluded[o.ConnectionID] != WithheldObservationBinding {
		excluded[o.ConnectionID] = reason
	}
}
