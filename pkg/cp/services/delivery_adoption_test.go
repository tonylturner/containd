// SPDX-License-Identifier: Apache-2.0
package services

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func TestDeliveryFreshAttemptAdoptsLiveProcesses(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "daemon")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nif [ \"$1\" = '-t' ] || [ \"$1\" = '--mode' ]; then exit 0; fi\nexec sleep 600\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	m := &Manager{Proxy: NewProxyManager(ProxyOptions{BaseDir: dir, Supervise: true, EnvoyPath: script, NginxPath: script})}
	t.Cleanup(func() { _ = m.Proxy.stopEnvoy(); _ = m.Proxy.stopNginx() })
	cfg := config.ServicesConfig{Proxy: daemonProxyConfig()}
	cfg.Proxy.Forward.Enabled = true
	meta := deliveryTestMeta()
	first, err := m.ApplyDelivery(context.Background(), meta, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, out := range first.Outcomes {
		if out.Acknowledged == nil {
			t.Fatalf("initial: %+v", out)
		}
	}
	forward, reverse := m.Proxy.Status()["envoy_pid"], m.Proxy.Status()["nginx_pid"]
	meta.ApplyID += "-fresh"
	meta.RunningRevision += "-fresh"
	adopted, err := m.ApplyDelivery(context.Background(), meta, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, out := range adopted.Outcomes {
		if out.Acknowledged == nil || out.Acknowledged.Metadata != meta || out.Attempt != 1 {
			t.Fatalf("not adopted: %+v", out)
		}
	}
	if m.Proxy.Status()["envoy_pid"] != forward || m.Proxy.Status()["nginx_pid"] != reverse {
		t.Fatal("fresh attempt restarted healthy owners")
	}
	// A changed reverse input selects only the reverse owner.
	cfg.Proxy.Reverse.Sites[0].ListenPort++
	meta.ApplyID += "-changed"
	changed, err := m.ApplyDelivery(context.Background(), meta, cfg, nil)
	if err != nil || outcomeFor(t, changed, protection.SubsystemReverseProxy).Attempt != 2 {
		t.Fatalf("changed delivery: %+v %v", changed, err)
	}
	if m.Proxy.Status()["envoy_pid"] != forward || m.Proxy.Status()["nginx_pid"] == reverse {
		t.Fatal("changed input did not select only reverse")
	}
	// Losing one runtime makes only that owner outstanding on the next attempt.
	if err := m.Proxy.stopNginx(); err != nil {
		t.Fatal(err)
	}
	meta.ApplyID += "-dead"
	recovered, err := m.ApplyDelivery(context.Background(), meta, cfg, nil)
	if err != nil || outcomeFor(t, recovered, protection.SubsystemReverseProxy).Acknowledged == nil || outcomeFor(t, recovered, protection.SubsystemReverseProxy).Attempt != 3 {
		t.Fatalf("dead runtime: %+v %v", recovered, err)
	}
	if m.Proxy.Status()["envoy_pid"] != forward || outcomeFor(t, recovered, protection.SubsystemForwardProxy).Attempt != 1 {
		t.Fatal("runtime loss restarted healthy peer")
	}
}

func TestDeliveryFreshAttemptPreservesOutstandingFault(t *testing.T) {
	m := &Manager{DNS: NewDNSManager(t.TempDir())}
	cfg := config.ServicesConfig{DNS: config.DNSConfig{Enabled: true}}
	invalid := []config.ServiceConfigError{{Service: config.ServiceDNS, Err: errors.New("invalid desired DNS")}}
	meta := deliveryTestMeta()
	first, err := m.ApplyDelivery(context.Background(), meta, cfg, invalid)
	if err != nil {
		t.Fatal(err)
	}
	meta.ApplyID += "-fresh"
	meta.RunningRevision += "-fresh"
	next, err := m.ApplyDelivery(context.Background(), meta, cfg, invalid)
	out := outcomeFor(t, next, protection.SubsystemDNS)
	if err != nil || out.Fault == nil || out.Acknowledged != nil || out.Attempt != outcomeFor(t, first, protection.SubsystemDNS).Attempt+1 || out.DesiredRevision != meta.RunningRevision {
		t.Fatalf("fault lost: %+v %v", out, err)
	}
}

func TestAVDeliveryFreshAttemptAdoptsConfirmedRuntime(t *testing.T) {
	server := startReadinessICAP(t, "127.0.0.1:0", healthyReadinessReply)
	m := newTestAVManager(t, AVOptions{})
	cfg := readinessICAPConfig(server)
	meta := deliveryTestMeta()
	first, err := m.ApplyDelivery(applyCtx(t), meta, cfg)
	if err != nil || first.Acknowledged == nil {
		t.Fatalf("initial: %+v %v", first, err)
	}
	m.mu.Lock()
	epoch, rendered := m.backendEpoch, m.lastRender
	m.mu.Unlock()
	meta.ApplyID += "-fresh"
	meta.RunningRevision += "-fresh"
	adopted, err := m.ApplyDelivery(applyCtx(t), meta, cfg)
	if err != nil || adopted.Acknowledged == nil || adopted.Acknowledged.Metadata != meta || adopted.Attempt != first.Attempt {
		t.Fatalf("not adopted: %+v %v", adopted, err)
	}
	m.mu.Lock()
	unchanged := m.backendEpoch == epoch && m.lastRender.Equal(rendered)
	m.mu.Unlock()
	if !unchanged {
		t.Fatal("healthy AV was reapplied")
	}
	server.stop()
	waitAVReady(t, m, false)
	meta.ApplyID += "-dead"
	failed, err := m.ApplyDelivery(applyCtx(t), meta, cfg)
	if err != nil || failed.Acknowledged != nil || !failed.Retryable || failed.Attempt != 2 {
		t.Fatalf("dead scanner was adopted: %+v %v", failed, err)
	}
}

func TestAVDeliveryTrustChangeRequiresFreshAttempt(t *testing.T) {
	ca := newTestCA(t, "delivery CA")
	other := newTestCA(t, "unrelated CA")
	m := newTestAVManager(t, AVOptions{})
	cfg := tlsICAPConfig(t, ca)
	meta := deliveryTestMeta()
	if err := m.SetTrust(context.Background(), mustBundle(t, ca.PEM)); err != nil {
		t.Fatal(err)
	}
	first, err := m.ApplyDelivery(applyCtx(t), meta, cfg)
	if err != nil || first.Acknowledged == nil {
		t.Fatalf("initial: %+v %v", first, err)
	}
	if err := m.SetTrust(context.Background(), mustBundle(t, other.PEM)); err != nil {
		t.Fatal(err)
	}
	if m.DeliveryOutcome().Acknowledged != nil {
		t.Fatal("trust change retained AV proof")
	}
	if _, err := m.RetryDelivery(context.Background(), meta); !errors.Is(err, ErrDeliverySuperseded) {
		t.Fatalf("changed trust reused attempt: %v", err)
	}
	meta.ApplyID += "-new-trust"
	next, err := m.ApplyDelivery(applyCtx(t), meta, cfg)
	if err != nil || next.Acknowledged != nil || next.Attempt != 2 {
		t.Fatalf("untrusted peer was adopted: %+v %v", next, err)
	}
	if err := m.SetTrust(context.Background(), mustBundle(t, ca.PEM)); err != nil {
		t.Fatal(err)
	}
	meta.ApplyID += "-recovered"
	next, err = m.ApplyDelivery(applyCtx(t), meta, cfg)
	if err != nil || next.Acknowledged == nil || next.Acknowledged.Metadata != meta {
		t.Fatalf("revalidated trust: %+v %v", next, err)
	}
}

func TestAVDeliveryUnselectedTrustDoesNotReplay(t *testing.T) {
	m := newTestAVManager(t, AVOptions{})
	meta := deliveryTestMeta()
	if _, err := m.StopDelivery(context.Background(), meta); err != nil {
		t.Fatal(err)
	}
	ca := newTestCA(t, "unselected CA")
	if err := m.SetTrust(context.Background(), mustBundle(t, ca.PEM)); err != nil {
		t.Fatal(err)
	}
	meta.ApplyID += "-fresh"
	out, err := m.StopDelivery(context.Background(), meta)
	if err != nil || out.Acknowledged == nil || out.Attempt != 1 {
		t.Fatalf("unrelated trust replayed disabled AV: %+v %v", out, err)
	}
}

func TestAVDeliveryCancelledBeforeMutationCannotAdopt(t *testing.T) {
	m := newTestAVManager(t, AVOptions{})
	meta := deliveryTestMeta()
	if _, err := m.StopDelivery(context.Background(), meta); err != nil {
		t.Fatal(err)
	}
	m.op <- struct{}{}
	defer m.unlock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	meta.ApplyID += "-cancelled"
	cfg := config.AVConfig{Enabled: true, Mode: "icap", ICAP: config.ICAPConfig{Servers: []config.ICAPServer{{Address: "127.0.0.1:1"}}}}
	out, err := m.ApplyDelivery(ctx, meta, cfg)
	if err != nil || out.Acknowledged != nil {
		t.Fatalf("cancelled apply: %+v %v", out, err)
	}
	if out := m.DeliveryOutcome(); out.Acknowledged != nil {
		t.Fatalf("old runtime certified undelivered input: %+v", out)
	}
}

func TestDeliveryChangedOwnerInvalidatesBeforeMutation(t *testing.T) {
	meta := deliveryTestMeta()
	old := deliveryOutcome(meta, protection.SubsystemDNS, protection.OwnerManagement, false, 1, nil)
	healthy := deliveryOutcome(meta, protection.SubsystemSyslog, protection.OwnerManagement, false, 1, nil)
	m := &Manager{delivery: deliveryState{meta: meta, desired: config.ServicesConfig{DNS: config.DNSConfig{Enabled: true}},
		outcomes: []protection.OwnerOutcome{old, healthy}, runtime: map[protection.SubsystemName]string{},
		inputs: map[protection.SubsystemName]any{protection.SubsystemDNS: struct {
			Config  any
			Invalid bool
		}{config.DNSConfig{}, false}},
	}}
	effective := m.delivery.desired
	var faults []ServiceFault
	called := false
	m.deliverOwnerLocked(context.Background(), protection.SubsystemDNS, config.ServiceDNS, true, false, true, func() error {
		called = true
		if m.delivery.outcomes[0].Acknowledged != nil {
			t.Fatal("changed owner retained proof during mutation")
		}
		if m.delivery.outcomes[1].Acknowledged == nil || m.delivery.outcomes[1].ObservedAt != healthy.ObservedAt {
			t.Fatal("unrelated owner was invalidated")
		}
		return errors.New("partial mutation failed")
	}, nil, &effective, &faults)
	if !called || m.delivery.outcomes[0].Acknowledged != nil || m.delivery.outcomes[0].Fault == nil {
		t.Fatal("partial mutation retained success")
	}
}
