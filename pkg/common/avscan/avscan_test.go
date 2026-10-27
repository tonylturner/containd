// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package avscan

import "testing"

func TestDecide(t *testing.T) {
	policies := []FailPolicy{FailOpen, FailClosed, "", "unknown"}
	unscanned := []Result{
		{Verdict: Unscanned, Reason: ReasonScannerError},
		{Verdict: Unscanned, Reason: ReasonTimeout},
		{Verdict: Unscanned, Reason: ReasonOversized},
		{Verdict: Unscanned, Reason: ReasonUnsupported},
		{Verdict: Unscanned, Reason: ReasonNotReady},
		{Verdict: Unscanned, Reason: ReasonBusy},
		{Verdict: ""},
		{Verdict: "maybe"},
	}
	for _, policy := range policies {
		for _, ics := range []bool{false, true} {
			for _, bypass := range []bool{false, true} {
				if got := Decide(Result{Verdict: Clean}, policy, ics, bypass); got != Deliver {
					t.Errorf("clean policy=%q ics=%v bypass=%v: %s", policy, ics, bypass, got)
				}
				if got := Decide(Result{Verdict: Infected, Signature: "Eicar"}, policy, ics, bypass); got != Block {
					t.Errorf("infected policy=%q ics=%v bypass=%v: %s", policy, ics, bypass, got)
				}
				want := Block
				if policy == FailOpen || (ics && bypass) {
					want = PassUnscanned
				}
				for _, r := range unscanned {
					if got := Decide(r, policy, ics, bypass); got != want {
						t.Errorf("%q/%q policy=%q ics=%v bypass=%v: %s, want %s", r.Verdict, r.Reason, policy, ics, bypass, got, want)
					}
				}
			}
		}
	}
}
