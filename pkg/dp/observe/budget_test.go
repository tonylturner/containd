// SPDX-License-Identifier: Apache-2.0
package observe

import (
	"errors"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/identify"
	"github.com/tonylturner/containd/pkg/dp/limits"
)

func TestObservationBudgetFailureIsTerminal(t *testing.T) {
	// Include the observer/identifier metadata and replay backing now charged
	// before the decoder is reached; leave too little for its stream admission.
	r := limits.NewResources(limits.NewBudget(8192), nil)
	o, decoder := newObserver(t, func(opts *Options) { opts.Manager.SetResources(r) })
	states := openTCP(t, o, "k")
	out := payload(o, "k", states, 0, 100, request)
	out.append(payload(o, "k", states, 1, 200, reply))
	refusals := 0
	for _, batch := range out.Batches {
		var se *dpi.StreamError
		if errors.As(batch.Err, &se) && se.Kind == dpi.StreamStateLimit {
			refusals++
		}
	}
	if refusals != 1 || len(decoder.sessions) != 0 {
		t.Fatalf("replay retried a refused decoder: %+v", out)
	}
	status, ok := o.Lookup("k")
	if !ok || status.Binding != None || status.Coverage != identify.Truncated {
		t.Fatalf("lost coverage was not retained: %+v", status)
	}
	for range 3 {
		if out := payload(o, "k", states, 0, 100, request); len(out.Batches) != 0 || len(out.Identifications) != 0 {
			t.Fatal("terminal marker resumed", out)
		}
	}
	hits := r.Ledger.Status(limits.TableInspection, limits.Occupancy{}).Hits
	if len(hits) != 1 || hits[0].Mode != limits.ModeMonitor || hits[0].Total != 1 {
		t.Fatalf("refusal transitions: %+v", hits)
	}
	o.Release("k")
	o.Drain()
	if r.Budget.Status().InUse != 0 {
		t.Fatal("released observation retained credit")
	}
}
