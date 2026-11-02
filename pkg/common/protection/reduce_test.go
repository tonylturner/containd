// SPDX-License-Identifier: Apache-2.0

package protection

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func cleanInput() Input {
	m := Metadata{BootID: "boot", ApplyID: "apply", RunningRevision: "running", Mode: ModeNormal}
	in := Input{
		DesiredRevision: m.RunningRevision, Current: m,
		DesiredTrustRevision: "none",
		Selection:            Selection{Forwarding: true, NFQueues: []uint16{42}, IECEnvelope: true, Scan: true, Trust: true},
		Engine: EngineObservation{Metadata: m, State: StateProtecting,
			Installed:  &Acknowledgement{Metadata: m, Operation: OperationApply},
			ObservedAt: time.Unix(100, 0).UTC()},
		Coherent: true, EnforcementEnabled: true,
	}
	for _, row := range Requirements(in.Selection) {
		in.Outcomes = append(in.Outcomes, OwnerOutcome{
			Name: row.Name, Owner: row.Owner, DesiredRevision: in.DesiredRevision,
			Operation: OperationApply, State: DeliveryReady,
			Acknowledged: &Acknowledgement{Metadata: m, Operation: OperationApply, TrustRevision: "none"},
			ObservedAt:   in.Engine.ObservedAt,
		})
	}
	return in
}

func outcome(in *Input, name SubsystemName) *OwnerOutcome {
	for i := range in.Outcomes {
		if in.Outcomes[i].Name == name {
			return &in.Outcomes[i]
		}
	}
	panic("missing test outcome: " + name)
}

func TestReduce(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Input)
		state   State
		applied Revision
		ready   bool
	}{
		{"clean", func(*Input) {}, StateProtecting, "running", true},
		{"no desired", func(in *Input) { in.DesiredRevision = "" }, StateUnknown, "running", false},
		{"candidate is not desired", func(in *Input) { in.DesiredRevision += "-candidate" }, StateUnknown, "running", false},
		{"unknown authority", func(in *Input) { in.Coherent = false }, StateUnknown, "", false},
		{"unknown boot", func(in *Input) { in.Current.BootID = "" }, StateUnknown, "", false},
		{"stale boot", func(in *Input) { in.Engine.BootID += "-old" }, StateUnknown, "", false},
		{"unknown observation", func(in *Input) { in.Engine.State = StateUnknown }, StateUnknown, "", false},
		{"missing observation", func(in *Input) { in.Engine.ObservedAt = time.Time{} }, StateUnknown, "", false},
		{"malformed observation", func(in *Input) { in.Engine.State = "surprise" }, StateUnknown, "", false},
		{"disabled", func(in *Input) { in.EnforcementEnabled = false }, StateDisabled, "", false},
		{"observed disabled", func(in *Input) { in.Engine.State = StateDisabled }, StateDisabled, "", false},
		{"recovery", func(in *Input) {
			in.Current.Mode = ModeRecovery
			in.Current.RunningRevision = RecoveryRevision(in.Current.BootID)
			in.Engine.Metadata = in.Current
		}, StateUnknown, "", false},
		{"uncertainty", func(in *Input) { in.Uncertain = true }, StateUnknown, "running", false},
		{"NFLOG degraded", func(in *Input) { in.Engine.State = StateDegraded }, StateDegraded, "running", false},
		{"schedule degraded", func(in *Input) { in.Degraded = true }, StateDegraded, "running", false},
		{"failed engine", func(in *Input) { in.Engine.State = StateFailed }, StateFailed, "running", false},
		{"pending engine", func(in *Input) { in.Engine.State = StatePending }, StatePending, "running", false},
		{"missing install", func(in *Input) { in.Engine.Installed = nil }, StatePending, "", false},
		{"old policy installed", func(in *Input) {
			in.Engine.Installed.RunningRevision += "-old"
			in.Engine.Installed.ApplyID += "-old"
		}, StatePending, "running-old", false},
		{"unadopted install", func(in *Input) { in.Engine.Installed.ApplyID += "-old" }, StatePending, "running", false},
		{"stale installed boot", func(in *Input) { in.Engine.Installed.BootID += "-old" }, StatePending, "", false},
		{"stale current attempt", func(in *Input) { in.Engine.ApplyID += "-old" }, StateUnknown, "running", false},
		{"trust unknown", func(in *Input) { in.DesiredTrustRevision = "" }, StatePending, "running", false},
		{"trust stale", func(in *Input) {
			outcome(in, SubsystemTrust).Acknowledged.TrustRevision = in.DesiredTrustRevision + "-old"
		}, StatePending, "running", false},
		{"duplicate owner", func(in *Input) {
			in.Outcomes = append(in.Outcomes, in.Outcomes[0])
		}, StateUnknown, "running", false},
		{"wrong owner", func(in *Input) { in.Outcomes[0].Owner = OwnerManagement }, StateUnknown, "running", false},
		{"unexpected owner", func(in *Input) {
			in.Outcomes = append(in.Outcomes, OwnerOutcome{Name: "invented"})
		}, StateUnknown, "running", false},
		{"zero queue", func(in *Input) { in.Selection.NFQueues = []uint16{0} }, StateUnknown, "running", false},
		{"duplicate queue", func(in *Input) { in.Selection.NFQueues = []uint16{42, 42} }, StateUnknown, "running", false},
		{"wall clock reversal", func(in *Input) {
			in.Engine.ObservedAt = time.Unix(1, 0)
			for i := range in.Outcomes {
				in.Outcomes[i].ObservedAt = time.Unix(1, 0)
			}
		}, StateProtecting, "running", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := cleanInput()
			tt.mutate(&in)
			got := Reduce(in)
			if got.Ready != tt.ready || got.State != tt.state {
				t.Fatalf("ready/state = %v/%s, want %v/%s", got.Ready, got.State, tt.ready, tt.state)
			}
			assertRevision(t, got.AppliedRevision, tt.applied)
			protecting := Revision("")
			if tt.ready {
				protecting = in.DesiredRevision
			}
			assertRevision(t, got.ProtectingRevision, protecting)
			assertRevision(t, got.DesiredRevision, in.DesiredRevision)
		})
	}
}

func assertRevision(t *testing.T, got *Revision, want Revision) {
	t.Helper()
	if want == "" {
		if got != nil {
			t.Fatalf("revision = %q, want null", *got)
		}
	} else if got == nil || *got != want {
		t.Fatalf("revision = %v, want %q", got, want)
	}
}

func TestEveryRequiredOwnerMustConfirmCurrentTarget(t *testing.T) {
	mutations := []struct {
		name string
		edit func(*OwnerOutcome)
	}{
		{"pending", func(o *OwnerOutcome) { o.State = DeliveryPending }},
		{"failed", func(o *OwnerOutcome) { o.State = DeliveryFailed }},
		{"unknown", func(o *OwnerOutcome) { o.State = DeliveryUnknown }},
		{"no ack", func(o *OwnerOutcome) { o.Acknowledged = nil }},
		{"stale boot", func(o *OwnerOutcome) { o.Acknowledged.BootID += "-old" }},
		{"stale attempt", func(o *OwnerOutcome) { o.Acknowledged.ApplyID += "-old" }},
		{"stale revision", func(o *OwnerOutcome) { o.Acknowledged.RunningRevision += "-old" }},
		{"stale desired", func(o *OwnerOutcome) { o.DesiredRevision += "-old" }},
		{"wrong mode", func(o *OwnerOutcome) { o.Acknowledged.Mode = ModeRecovery }},
		{"missing observation", func(o *OwnerOutcome) { o.ObservedAt = time.Time{} }},
		{"fault with old success", func(o *OwnerOutcome) {
			o.Fault = &Fault{Kind: FaultDelivery, Reason: "partial mutation"}
		}},
		{"off without stop", func(o *OwnerOutcome) { o.State = DeliveryOff }},
		{"wrong operation", func(o *OwnerOutcome) { o.Operation = OperationStop }},
	}
	for _, row := range Requirements(cleanInput().Selection) {
		if !row.Required {
			continue
		}
		t.Run(string(row.Name), func(t *testing.T) {
			for _, mutation := range mutations {
				t.Run(mutation.name, func(t *testing.T) {
					in := cleanInput()
					mutation.edit(outcome(&in, row.Name))
					if got := Reduce(in); got.Ready || got.ProtectingRevision != nil {
						t.Fatalf("unconfirmed owner protects: %+v", got)
					}
				})
			}
			t.Run("missing owner", func(t *testing.T) {
				in := cleanInput()
				for i, o := range in.Outcomes {
					if o.Name == row.Name {
						in.Outcomes = append(in.Outcomes[:i], in.Outcomes[i+1:]...)
						break
					}
				}
				got := Reduce(in)
				if got.Ready {
					t.Fatal("missing owner protects")
				}
				for _, status := range got.Subsystems {
					if status.Name == row.Name && (!status.Required || status.State != DeliveryUnknown) {
						t.Fatalf("missing owner not visible/required: %+v", status)
					}
				}
			})
			if !row.AllowStop {
				t.Run("cannot stop an enforcement prerequisite", func(t *testing.T) {
					in := cleanInput()
					o := outcome(&in, row.Name)
					o.Operation, o.State = OperationStop, DeliveryOff
					o.Acknowledged.Operation = OperationStop
					if Reduce(in).Ready {
						t.Fatal("absence substituted for an enforcement prerequisite")
					}
				})
			}
		})
	}
}

func TestNonGatingFaultsRemainVisible(t *testing.T) {
	for _, name := range []SubsystemName{SubsystemDNS, SubsystemNTP, SubsystemSyslog, SubsystemDHCP, SubsystemAV} {
		t.Run(string(name), func(t *testing.T) {
			in := cleanInput()
			o := outcome(&in, name)
			o.State, o.Acknowledged, o.Retryable = DeliveryFailed, nil, true
			o.Fault = &Fault{Kind: FaultDelivery, Reason: "start failed"}
			got := Reduce(in)
			if !got.Ready {
				t.Fatalf("non-gating failure blocks: %+v", got)
			}
			for _, status := range got.Subsystems {
				if status.Name == name && (status.Required || status.Fault == nil ||
					!status.Retryable || status.State != DeliveryFailed) {
					t.Fatalf("fault hidden or gating: %+v", status)
				}
			}
		})
	}
}

func TestTrafficServiceTeardownRequiresVerifiedAbsence(t *testing.T) {
	for _, name := range []SubsystemName{SubsystemOpenVPN, SubsystemWireGuard, SubsystemForwardProxy, SubsystemReverseProxy} {
		t.Run(string(name), func(t *testing.T) {
			in := cleanInput()
			o := outcome(&in, name)
			o.Operation, o.State = OperationStop, DeliveryFailed
			o.Acknowledged = nil
			o.Fault = &Fault{Kind: FaultDelivery, Reason: "stop failed"}
			if got := Reduce(in); got.Ready || got.State != StateFailed {
				t.Fatal("teardown failure did not gate")
			}
			o.Fault, o.State = nil, DeliveryOff
			if Reduce(in).Ready {
				t.Fatal("desired disabled was mistaken for proof")
			}
			o.Acknowledged = &Acknowledgement{Metadata: in.Current, Operation: OperationStop}
			if !Reduce(in).Ready {
				t.Fatal("verified absence did not discharge teardown")
			}
		})
	}
}

func TestReduceReturnsDetachedDeterministicSnapshot(t *testing.T) {
	in := cleanInput()
	o := outcome(&in, SubsystemDNS)
	o.Fault = &Fault{Kind: FaultDelivery, Reason: "original"}
	next := time.Unix(200, 0)
	o.NextRetryAt = &next
	before, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	got := Reduce(in)
	after, err := json.Marshal(in)
	if err != nil || string(before) != string(after) {
		t.Fatal("reducer mutated input")
	}
	if !reflect.DeepEqual(got, Reduce(in)) {
		t.Fatal("nondeterministic reduction")
	}
	for i := range got.Subsystems {
		s := &got.Subsystems[i]
		if s.Name == SubsystemDNS {
			s.Fault.Reason = "changed"
			s.Acknowledged.ApplyID = "changed"
			*s.NextRetryAt = time.Time{}
		}
	}
	if o.Fault.Reason != "original" || o.Acknowledged.ApplyID != in.Current.ApplyID ||
		o.NextRetryAt.IsZero() {
		t.Fatal("output aliases input")
	}
}
