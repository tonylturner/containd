// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestMissingZoneAttachments(t *testing.T) {
	snap := &rules.Snapshot{
		ZoneIfaces: map[string][]string{
			"firewall": {"fw2", "fw1"}, "nat-source": {"src"}, "nat-egress": {"egress"},
			"publish": {"pub"}, "local": {"dns"}, "wan": {"wan0"},
			"unreferenced": {"unused"}, "zero-row": {},
		},
		Firewall: []rules.Entry{{SourceZones: []string{"firewall", "zero-row"}, DestZones: []string{"firewall"}}},
		NAT: rules.NATConfig{Enabled: true, SourceZones: []string{"nat-source"}, EgressZone: "nat-egress",
			PortForwards: []rules.PortForward{{Enabled: true, IngressZone: "publish"}}},
		LocalInput: []rules.LocalServiceRule{{Zone: "local"}, {ID: "auto-allow-wireguard", Zone: "wan"}},
	}
	want := "zone firewall has no attached interface: fw1, fw2; zone local has no attached interface: dns; zone nat-egress has no attached interface: egress; zone nat-source has no attached interface: src; zone publish has no attached interface: pub; zone wan has no attached interface: wan0"
	if got := missingZoneAttachments(snap, nil); got != want {
		t.Fatalf("reason = %q, want %q", got, want)
	}
	if got := missingZoneAttachments(snap, []string{"fw2", "src", "egress", "pub", "dns", "wan0"}); got != "" {
		t.Fatalf("one existing device per zone must suffice: %s", got)
	}
	snap.NAT.Enabled = false
	snap.Firewall, snap.LocalInput = nil, nil
	if got := missingZoneAttachments(snap, nil); got != "zone publish has no attached interface: pub" {
		t.Fatalf("publishing was coupled to source NAT: %q", got)
	}
	snap.NAT.PortForwards[0].Enabled = false
	snap.LocalInput = []rules.LocalServiceRule{{Ifaces: []string{"literal"}, Zone: "local"}}
	if got := missingZoneAttachments(snap, nil); got != "" {
		t.Fatalf("inactive or overridden zone reference raised a fault: %q", got)
	}
}

func TestProtectionInterfaceAttachment(t *testing.T) {
	e, _ := admissionEngine(t)
	t.Cleanup(e.Close)
	m := protection.Metadata{BootID: "boot", ApplyID: "attachment", RunningRevision: "running", Mode: protection.ModeNormal}
	e.BindProtection(m)
	snap := rules.Snapshot{Default: rules.ActionDeny, ZoneIfaces: map[string][]string{"lan": {"lan2", "lan1"}},
		Firewall: []rules.Entry{{SourceZones: []string{"lan"}, Action: rules.ActionDeny}}}
	if err := e.ApplyRules(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	ack := protection.Acknowledgement{Metadata: m, Operation: protection.OperationApply}
	e.SetProtectionOutcome(m, protection.OwnerOutcome{
		Name: protection.SubsystemInterfaces, Owner: protection.OwnerEngine, DesiredRevision: m.RunningRevision,
		Operation: protection.OperationApply, State: protection.DeliveryReady, Acknowledged: &ack, ObservedAt: time.Now(),
	})
	before := e.Protection()
	installed := e.RulesetStatus()
	e.reconcileInterfaceAttachment(m, func() ([]string, error) { return nil, nil })
	degraded := e.Protection()
	c := protectionComponent(t, degraded, "interface-attachment")
	if degraded.State != "degraded" || degraded.Retryable || c.State != "degraded" ||
		c.Reason != "zone lan has no attached interface: lan1, lan2" {
		t.Fatalf("missing attachment: %+v", degraded)
	}
	if !reflect.DeepEqual(installed, e.RulesetStatus()) || !reflect.DeepEqual(before.Installed, degraded.Installed) {
		t.Fatal("attachment observation modified the installed policy")
	}
	for _, out := range degraded.Subsystems {
		if out.Name == protection.SubsystemInterfaces && (out.State != protection.DeliveryReady ||
			out.Acknowledged == nil || *out.Acknowledged != ack || out.Fault != nil || out.Retryable) {
			t.Fatalf("attachment invalidated interface delivery: %+v", out)
		}
	}
	e.reconcileInterfaceAttachment(m, func() ([]string, error) { return nil, errors.New("discovery unavailable") })
	unknown := e.Protection()
	if unknown.State != "unknown" || unknown.Retryable ||
		protectionComponent(t, unknown, "interface-attachment").State != "unknown" {
		t.Fatalf("discovery failure was interpreted as missing: %+v", unknown)
	}
	e.reconcileInterfaceAttachment(m, func() ([]string, error) { return []string{"lan1"}, nil })
	ready := e.Protection()
	if ready.State != "protecting" || ready.Retryable || protectionComponent(t, ready, "interface-attachment").Reason != "" {
		t.Fatalf("attachment did not clear fault: %+v", ready)
	}
	stale := m
	stale.ApplyID += "-old"
	e.reconcileInterfaceAttachment(stale, func() ([]string, error) {
		t.Fatal("stale attempt performed discovery")
		return nil, nil
	})
	if e.Protection().State != "protecting" {
		t.Fatal("stale attempt published a fault")
	}
	// Supersession during discovery must also exclude publication.
	e.reconcileInterfaceAttachment(m, func() ([]string, error) {
		next := m
		next.ApplyID += "-new"
		e.BindProtection(next)
		return nil, nil
	})
	if e.Protection().State != "protecting" {
		t.Fatal("superseded discovery published a fault")
	}
}
