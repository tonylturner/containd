// SPDX-License-Identifier: Apache-2.0
//go:build linux

package dhcpd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func dhcpDeliveryMeta() protection.Metadata {
	return protection.Metadata{BootID: "boot", ApplyID: "apply", RunningRevision: "revision", Mode: protection.ModeNormal}
}

func fakeDeliveryNFT(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	marker := filepath.Join(dir, "fail")
	script := "#!/bin/sh\nif [ -f '" + marker + "' ]; then exit 1; fi\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	return marker
}

func TestDeliveryDHCPFailedDisableRetriesOwner(t *testing.T) {
	marker := fakeDeliveryNFT(t)
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	m := NewManager()
	out, err := m.StopDelivery(context.Background(), dhcpDeliveryMeta())
	if err != nil || out.Acknowledged != nil || !out.Retryable || out.Fault.Kind != protection.FaultDelivery {
		t.Fatalf("failed disable: %+v %v", out, err)
	}
	if err := os.Rename(marker, marker+".recovered"); err != nil {
		t.Fatal(err)
	}
	out, err = m.RetryDelivery(context.Background(), dhcpDeliveryMeta())
	if err != nil || out.Acknowledged == nil || out.State != protection.DeliveryOff || out.Attempt != 2 {
		t.Fatalf("retry stop: %+v %v", out, err)
	}
	meta := dhcpDeliveryMeta()
	meta.ApplyID = protection.ApplyID(string(meta.ApplyID) + "-other")
	if _, err := m.RetryDelivery(context.Background(), meta); !errors.Is(err, ErrDeliverySuperseded) {
		t.Fatal("stale retry accepted")
	}
	if err := m.Apply(context.Background(), config.DHCPConfig{}, nil); err != nil {
		t.Fatal(err)
	}
	if m.DeliveryOutcome().Acknowledged != nil {
		t.Fatal("direct apply retained old ack")
	}
}

func TestDeliveryDHCPCancelledStopRetainsJoin(t *testing.T) {
	fakeDeliveryNFT(t)
	m := NewManager()
	done := make(chan struct{})
	m.listeners["lan"] = listener{cancel: func() {}, done: done}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out, err := m.StopDelivery(ctx, dhcpDeliveryMeta())
	if err != nil || out.Acknowledged != nil || !out.Retryable {
		t.Fatalf("unjoined stop certified: %+v %v", out, err)
	}
	if len(m.stopping) != 1 {
		t.Fatal("lost pending join after cancellation")
	}
	close(done)
	out, err = m.RetryDelivery(context.Background(), dhcpDeliveryMeta())
	if err != nil || out.Acknowledged == nil || len(m.stopping) != 0 {
		t.Fatalf("joined stop not recovered: %+v %v", out, err)
	}
}

func TestDeliveryDHCPReadinessRevokesProof(t *testing.T) {
	m := NewManager()
	ready, done := make(chan struct{}), make(chan struct{})
	m.listeners["lan"] = listener{ready: ready, done: done}
	m.delivery.meta = dhcpDeliveryMeta()
	m.delivery.cfg.Enabled = true
	m.delivery.applied = true
	m.delivery.outcome = m.makeOutcome(dhcpDeliveryMeta(), true, 1, nil)
	if out := m.DeliveryOutcome(); out.Acknowledged != nil || out.State != protection.DeliveryPending {
		t.Fatalf("early ack: %+v", out)
	}
	close(ready)
	if out := m.DeliveryOutcome(); out.Acknowledged == nil {
		t.Fatalf("ready listener not adopted: %+v", out)
	}
	close(done)
	if out := m.DeliveryOutcome(); out.Acknowledged != nil {
		t.Fatalf("dead listener kept proof: %+v", out)
	}
}

func TestDeliveryDHCPConfigFaultIsTerminal(t *testing.T) {
	fakeDeliveryNFT(t)
	m := NewManager()
	out, err := m.ApplyDelivery(context.Background(), dhcpDeliveryMeta(), config.DHCPConfig{Enabled: true, Pools: []config.DHCPPool{{Iface: "lan", Start: "invalid", End: "invalid"}}}, nil)
	if err != nil || out.Fault == nil || out.Fault.Kind != protection.FaultConfig || out.Retryable {
		t.Fatalf("config fault: %+v %v", out, err)
	}
	out, err = m.RetryDelivery(context.Background(), dhcpDeliveryMeta())
	if err != nil || out.Attempt != 1 {
		t.Fatal("terminal input retried")
	}
	// Explicit repair/disable must not retain omitted fields from the rejected
	// input in the manager's detached retry snapshot.
	meta := dhcpDeliveryMeta()
	meta.ApplyID = protection.ApplyID(string(meta.ApplyID) + "-stop")
	out, err = m.StopDelivery(context.Background(), meta)
	if err != nil || out.Acknowledged == nil {
		t.Fatalf("stop retained rejected pools: %+v %v", out, err)
	}
}

func TestDeliveryDHCPFreshAttemptAdoptsConfirmedStop(t *testing.T) {
	fakeDeliveryNFT(t)
	m := NewManager()
	meta := dhcpDeliveryMeta()
	first, err := m.StopDelivery(context.Background(), meta)
	if err != nil || first.Acknowledged == nil {
		t.Fatalf("stop: %+v %v", first, err)
	}
	applied := m.lastApply
	meta.ApplyID += "-fresh"
	meta.RunningRevision += "-fresh"
	adopted, err := m.StopDelivery(context.Background(), meta)
	if err != nil || adopted.Acknowledged == nil || adopted.Acknowledged.Metadata != meta || adopted.Attempt != 1 || !m.lastApply.Equal(applied) {
		t.Fatalf("stop was replayed instead of adopted: %+v %v", adopted, err)
	}
	// An outstanding join makes absence undecidable. It must be delivered, not
	// silently re-labelled as a successful stop on another fresh attempt.
	done := make(chan struct{})
	m.stopping = append(m.stopping, done)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	meta.ApplyID += "-outstanding"
	failed, err := m.StopDelivery(ctx, meta)
	if err != nil || failed.Acknowledged != nil || !failed.Retryable || failed.Attempt != 2 {
		t.Fatalf("unjoined runtime adopted: %+v %v", failed, err)
	}
	meta.ApplyID += "-again"
	failed, err = m.StopDelivery(ctx, meta)
	if err != nil || failed.Acknowledged != nil || !failed.Retryable || failed.Attempt != 3 {
		t.Fatalf("failure lost across fresh attempt: %+v %v", failed, err)
	}
	close(done)
}
