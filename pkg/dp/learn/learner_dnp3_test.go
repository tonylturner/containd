// SPDX-License-Identifier: Apache-2.0
package learn

import (
	"encoding/hex"
	"slices"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/dnp3"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields/decodertest"
)

func TestDNP3OperateFromWireIsLearned(t *testing.T) {
	// Master 1 to outstation 10, FC4 Operate, one CROB at index 0:
	// latch on once, 100 ms on, zero off. Link and data CRCs included.
	wire, err := hex.DecodeString("056418c40a0001003d3ac0c0040c011701000301640000000000bd76000000ffff")
	if err != nil {
		t.Fatal(err)
	}
	res, err := dnp3.NewDecoder().ParseStream(nil, dpi.StreamView{Bytes: wire})
	if err != nil || len(res.Frames) != 1 || len(res.Frames[0].Events) != 1 {
		t.Fatalf("decode=%+v err=%v", res, err)
	}
	ev := res.Frames[0].Events[0]
	for form, attrs := range decodertest.Forms(t, ev.Attributes) {
		t.Run(form, func(t *testing.T) {
			event := ev
			event.Attributes = attrs
			learner := New()
			learner.RecordEvent("192.0.2.1", "192.0.2.2", event)
			profiles := learner.Profiles()
			if len(profiles) != 1 || !profiles[0].FunctionCodes[4] ||
				!profiles[0].WriteSeen || profiles[0].ReadSeen {
				t.Fatalf("operate profile missing or misclassified: %+v", profiles)
			}
			generated := learner.GenerateRules()
			if len(generated) != 1 {
				t.Fatalf("operate generated %d rules, want 1", len(generated))
			}
			predicate := generated[0].ICS
			if predicate.Protocol != eventfields.ProtoDNP3 ||
				predicate.Direction != eventfields.KindRequest ||
				!slices.Equal(predicate.FunctionCode, []uint8{4}) ||
				!predicate.WriteOnly || predicate.ReadOnly {
				t.Fatalf("operate predicate=%+v", predicate)
			}
		})
	}
}
