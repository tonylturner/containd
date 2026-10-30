// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"testing"

	"github.com/tonylturner/containd/pkg/dp/identify"
)

func TestStopDiscardsEvidenceAndBinding(t *testing.T) {
	for _, bound := range []bool{false, true} {
		o, decoder := newObserver(t, nil)
		s := openTCP(t, o, "k")
		payload(o, "k", s, 0, 100, request)
		if bound {
			payload(o, "k", s, 1, 200, reply)
		}
		before := len(decoder.sessions)
		o.Stop("k")
		o.Stop("k")
		out := payload(o, "k", s, 1, 200, reply)
		out.append(o.Finish("k"))
		if len(out.Batches) != 0 || len(out.Identifications) != 0 || len(decoder.sessions) != before {
			t.Fatal("stop replayed evidence or continued decoding")
		}
		if counts := o.Counters(); counts.Entries != 0 || counts.ChargedBytes != 0 || counts.Bindings != 0 || counts.Markers != 1 {
			t.Fatalf("stop did not release evidence/binding: %+v", counts)
		}
		if o.Open("k", identify.Meta{Transport: 6}) {
			t.Fatal("loss marker reopened without incarnation retirement")
		}
		o.Release("k")
		if !o.Open("k", identify.Meta{Transport: 6}) {
			t.Fatal("new incarnation could not open")
		}
	}
}
