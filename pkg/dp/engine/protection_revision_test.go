// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestProtectionResolvedManagementBindings(t *testing.T) {
	snap := rules.Snapshot{LocalInput: []rules.LocalServiceRule{{
		ID: "management", Ifaces: []string{"bound0"}, DeniedIfaces: []string{"denied0"}, RecoverUnbound: true,
	}}}
	discover := func(devices ...string) func() ([]string, error) {
		return func() ([]string, error) { return devices, nil }
	}
	first, err := protectionPolicyInput(snap, [32]byte{}, discover("bound0", "other0"))
	if err != nil {
		t.Fatal(err)
	}
	same, err := protectionPolicyInput(snap, [32]byte{}, discover("bound0", "unrelated0"))
	if err != nil || !bytes.Equal(first, same) {
		t.Fatalf("unrelated device invalidated resolved policy: %v", err)
	}
	changed, err := protectionPolicyInput(snap, [32]byte{}, discover("replacement0", "denied0"))
	if err != nil || bytes.Equal(first, changed) || bytes.Contains(changed, []byte(`"Devices":["denied0"`)) {
		t.Fatalf("changed management binding was not fenced: %s %v", changed, err)
	}
}

func TestProtectionResolvedPolicyRequiresNewAttempt(t *testing.T) {
	e, _ := admissionEngine(t)
	m := protection.Metadata{BootID: "boot", ApplyID: "first", RunningRevision: "running", Mode: protection.ModeNormal}
	e.BindProtection(m)
	address := netip.MustParseAddr("192.0.2.1")
	e.localIPv4 = func(*rules.Snapshot) (map[string][]netip.Addr, error) {
		return map[string][]netip.Addr{"wan0": {address}}, nil
	}
	snap := rules.Snapshot{Version: "stable", Default: rules.ActionDeny}
	if err := e.ApplyRules(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	installed := e.RulesetStatus()
	if st := e.Protection(); st.Installed == nil || st.Installed.Metadata != m {
		t.Fatalf("missing installed revision: %+v", st)
	}
	// Same target is a positive snapshot-equality adoption, not a new install.
	m.ApplyID = "adopted"
	e.BindProtection(m)
	if err := e.ApplyRules(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(e.RulesetStatus(), installed) || e.Protection().Installed.Metadata != m {
		t.Fatal("adoption manufactured an install timestamp or lost association")
	}
	// Resolution may change even when the submitted snapshot bytes do not.
	address = address.Next()
	before := e.Protection()
	if err := e.ApplyRules(context.Background(), snap); !errors.Is(err, ErrResolvedPolicyChanged) {
		t.Fatalf("changed resolution reused attempt: %v", err)
	}
	after := e.Protection()
	before.ObservedAt = after.ObservedAt
	for i := range before.Subsystems {
		before.Subsystems[i].ObservedAt = after.Subsystems[i].ObservedAt
	}
	if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(e.RulesetStatus(), installed) {
		t.Fatal("rejected resolved input mutated observation or installed policy")
	}
	m.ApplyID = "recovered-projection"
	e.BindProtection(m)
	if err := e.ApplyRules(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	if e.Protection().Installed.Metadata != m || e.RulesetStatus().AppliedAt == installed.AppliedAt {
		t.Fatal("new resolved policy was not freshly installed")
	}
}

func TestProtectionOwnerCompletionRejectsStaleMetadataAndDetaches(t *testing.T) {
	e, _ := admissionEngine(t)
	old := protection.Metadata{BootID: "boot", ApplyID: "old", RunningRevision: "running", Mode: protection.ModeNormal}
	current := old
	current.ApplyID = "current"
	e.BindProtection(current)
	o := protection.OwnerOutcome{Name: protection.SubsystemInterfaces, Owner: protection.OwnerEngine,
		DesiredRevision: current.RunningRevision, State: protection.DeliveryReady,
		Acknowledged: &protection.Acknowledgement{Metadata: old, Operation: protection.OperationApply}}
	e.SetProtectionOutcome(old, o)
	for _, got := range e.Protection().Subsystems {
		if got.Name == o.Name {
			t.Fatal("stale owner callback was accepted")
		}
	}
	o.Acknowledged.Metadata = current
	e.SetProtectionOutcome(current, o)
	o.Acknowledged.ApplyID = "mutated-caller"
	st := e.Protection()
	st.Installed = &protection.Acknowledgement{Metadata: old}
	for _, got := range st.Subsystems {
		if got.Name == o.Name {
			if got.Acknowledged.Metadata != current {
				t.Fatal("owner retained mutable caller acknowledgement")
			}
			got.Acknowledged.ApplyID = "mutated-reader"
		}
	}
	for _, got := range e.Protection().Subsystems {
		if got.Name == o.Name && got.Acknowledged.Metadata != current {
			t.Fatal("observation exposed mutable acknowledgement")
		}
	}
}
