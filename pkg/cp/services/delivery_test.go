// SPDX-License-Identifier: Apache-2.0
package services

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func outcomeFor(t *testing.T, result DeliveryResult, name protection.SubsystemName) protection.OwnerOutcome {
	t.Helper()
	for _, out := range result.Outcomes {
		if out.Name == name {
			return out
		}
	}
	t.Fatalf("missing %s outcome", name)
	return protection.OwnerOutcome{}
}

func TestDeliveryRetryFailedOwnerOnly(t *testing.T) {
	m := NewManager(ManagerOptions{BaseDir: t.TempDir()})
	m.NTP, m.Proxy, m.VPN, m.DHCP = nil, nil, nil, nil
	m.DNS.Supervise = false
	dir := m.DNS.BaseDir
	m.DNS.BaseDir = filepath.Join(dir, "broken")
	if err := os.WriteFile(m.DNS.BaseDir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	events := 0
	m.Syslog.OnEvent = func(string, map[string]any) { events++ }
	cfg := config.ServicesConfig{DNS: config.DNSConfig{Enabled: true}}
	meta := deliveryTestMeta()
	result, err := m.ApplyDelivery(context.Background(), meta, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	failed := outcomeFor(t, result, protection.SubsystemDNS)
	if failed.Fault == nil || failed.Fault.Kind != protection.FaultDelivery || !failed.Retryable || failed.Acknowledged != nil {
		t.Fatalf("wrong transient failure: %+v", failed)
	}
	healthy := outcomeFor(t, result, protection.SubsystemSyslog)
	if healthy.Acknowledged == nil {
		t.Fatal("healthy owner not acknowledged")
	}
	before := events
	m.DNS.BaseDir = dir
	cfg.DNS.Enabled = false // retry must retain a detached original input
	result, err = m.RetryDelivery(context.Background(), meta)
	if err != nil {
		t.Fatal(err)
	}
	recovered := outcomeFor(t, result, protection.SubsystemDNS)
	if recovered.State != protection.DeliveryReady || recovered.Attempt != 2 || !result.Effective.DNS.Enabled {
		t.Fatalf("did not recover original input: %+v", result)
	}
	if events != before || outcomeFor(t, result, protection.SubsystemSyslog).ObservedAt != healthy.ObservedAt {
		t.Fatal("retry reapplied healthy syslog")
	}
	recovered.Acknowledged.ApplyID = "mutated"
	if m.DeliveryOutcomes()[1].Acknowledged.ApplyID != meta.ApplyID {
		t.Fatal("outcome aliased owner state")
	}
	stale := meta
	stale.ApplyID = protection.ApplyID(string(meta.ApplyID) + "-stale")
	if _, err := m.RetryDelivery(context.Background(), stale); !errors.Is(err, ErrDeliverySuperseded) {
		t.Fatalf("stale retry accepted: %v", err)
	}
}

func TestDeliveryFaultKindsAndSecretDiagnostics(t *testing.T) {
	for _, kind := range []protection.FaultKind{protection.FaultConfig, protection.FaultRender} {
		t.Run(string(kind), func(t *testing.T) {
			m := NewManager(ManagerOptions{BaseDir: t.TempDir()})
			m.Syslog, m.NTP, m.Proxy, m.VPN, m.DHCP = nil, nil, nil, nil, nil
			m.DNS.Supervise = false
			cfg := config.ServicesConfig{DNS: config.DNSConfig{Enabled: true}}
			var initial []config.ServiceConfigError
			const secret = "password-NEVER-PUBLISH"
			if kind == protection.FaultConfig {
				initial = []config.ServiceConfigError{{Service: config.ServiceDNS, Err: errors.New(secret)}}
			} else {
				script := filepath.Join(t.TempDir(), "reject")
				if err := os.WriteFile(script, []byte("#!/bin/sh\necho '"+secret+"' >&2\nexit 1\n"), 0o700); err != nil {
					t.Fatal(err)
				}
				m.DNS.CheckConfPath = script
			}
			result, err := m.ApplyDelivery(context.Background(), deliveryTestMeta(), cfg, initial)
			if err != nil {
				t.Fatal(err)
			}
			out := outcomeFor(t, result, protection.SubsystemDNS)
			if out.Fault == nil || out.Fault.Kind != kind || out.Retryable || out.Acknowledged != nil {
				t.Fatalf("wrong terminal fault: %+v", out)
			}
			snapshot, _ := json.Marshal(struct {
				Outcomes []protection.OwnerOutcome
				Faults   []ServiceFault
			}{result.Outcomes, m.Faults()})
			if strings.Contains(string(snapshot), secret) {
				t.Fatalf("secret in diagnostics: %s", snapshot)
			}
			result, err = m.RetryDelivery(context.Background(), deliveryTestMeta())
			if err != nil || outcomeFor(t, result, protection.SubsystemDNS).Attempt != 1 {
				t.Fatal("terminal input fault retried")
			}
		})
	}
}

func TestDeliveryFailedDisableThenVerifiedStop(t *testing.T) {
	for _, name := range []protection.SubsystemName{protection.SubsystemOpenVPN, protection.SubsystemForwardProxy, protection.SubsystemReverseProxy} {
		t.Run(string(name), func(t *testing.T) {
			cmd, done := daemonSentinel(t)
			m := NewManager(ManagerOptions{BaseDir: t.TempDir()})
			m.Syslog, m.DNS, m.NTP, m.DHCP = nil, nil, nil, nil
			switch name {
			case protection.SubsystemOpenVPN:
				m.Proxy = nil
				m.VPN.ovpnCmd = cmd
				m.VPN.ovpnRunning = true
			case protection.SubsystemForwardProxy:
				m.VPN = nil
				m.Proxy.envoyCmd = cmd
			case protection.SubsystemReverseProxy:
				m.VPN = nil
				m.Proxy.nginxCmd = cmd
			}
			result, err := m.StopDelivery(context.Background(), deliveryTestMeta())
			if err != nil {
				t.Fatal(err)
			}
			out := outcomeFor(t, result, name)
			if out.Operation != protection.OperationStop || out.Acknowledged != nil || !out.Retryable {
				t.Fatalf("unverified stop acknowledged: %+v", out)
			}
			switch name {
			case protection.SubsystemOpenVPN:
				m.VPN.ovpnWaitCh = done
			case protection.SubsystemForwardProxy:
				m.Proxy.envoyDone = done
			case protection.SubsystemReverseProxy:
				m.Proxy.nginxDone = done
			}
			result, err = m.RetryDelivery(context.Background(), deliveryTestMeta())
			if err != nil {
				t.Fatal(err)
			}
			out = outcomeFor(t, result, name)
			if out.State != protection.DeliveryOff || out.Acknowledged == nil || out.Acknowledged.Operation != protection.OperationStop || out.Attempt != 2 {
				t.Fatalf("verified stop not recovered: %+v", out)
			}
			select {
			case <-done:
			default:
				t.Fatal("stop returned before reaping")
			}
		})
	}
}

func TestDeliveryQuarantineStopNotAcknowledged(t *testing.T) {
	cmd, done := daemonSentinel(t)
	m := NewManager(ManagerOptions{BaseDir: t.TempDir()})
	m.Syslog, m.DNS, m.NTP, m.DHCP, m.Proxy = nil, nil, nil, nil, nil
	m.VPN.ovpnCmd, m.VPN.ovpnRunning = cmd, true
	cfg := config.ServicesConfig{VPN: config.VPNConfig{OpenVPN: config.OpenVPNConfig{Enabled: true, Mode: "invalid"}}}
	result, err := m.ApplyDelivery(context.Background(), deliveryTestMeta(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	out := outcomeFor(t, result, protection.SubsystemOpenVPN)
	if out.Fault == nil || out.Fault.Kind != protection.FaultConfig || out.Acknowledged != nil || !strings.Contains(out.Reason, "quarantine stop not confirmed") {
		t.Fatalf("false quarantine proof: %+v", out)
	}
	m.VPN.ovpnWaitCh = done
}

func TestDeliveryDHCPRenderIsNotRuntimeProof(t *testing.T) {
	m := &Manager{DHCP: NewDHCPManager(t.TempDir())}
	result, err := m.StopDelivery(context.Background(), deliveryTestMeta())
	if err != nil {
		t.Fatal(err)
	}
	out := outcomeFor(t, result, protection.SubsystemDHCP)
	if out.Owner != protection.OwnerEngine || out.Acknowledged != nil || out.State != protection.DeliveryPending {
		t.Fatalf("render claimed engine stop: %+v", out)
	}
}

func TestAVDeliveryPreservesExistingOwner(t *testing.T) {
	m := newTestAVManager(t, AVOptions{})
	out, err := m.StopDelivery(context.Background(), deliveryTestMeta())
	if err != nil || out.Acknowledged == nil || out.State != protection.DeliveryOff {
		t.Fatalf("AV stop: %+v %v", out, err)
	}
	if err := m.Apply(context.Background(), config.AVConfig{}); err != nil {
		t.Fatal(err)
	}
	if m.DeliveryOutcome().Acknowledged != nil {
		t.Fatal("unlabelled apply retained stale proof")
	}
	if _, err := m.RetryDelivery(context.Background(), deliveryTestMeta()); !errors.Is(err, ErrDeliverySuperseded) {
		t.Fatal("unlabelled mutation did not invalidate delivery identity")
	}
}

func TestDeliveryProxyRetryPreservesHealthyPeer(t *testing.T) {
	dir := t.TempDir()
	fail := filepath.Join(dir, "fail")
	if err := os.WriteFile(fail, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "daemon")
	body := "#!/bin/sh\nif [ \"$1\" = '-t' ] || [ \"$1\" = '--mode' ]; then exit 0; fi\nif [ \"$1\" = '-c' ] && [ -f '" + fail + "' ] && [ \"$3\" = '--log-level' ]; then exit 1; fi\nexec sleep 600\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	m := &Manager{Proxy: NewProxyManager(ProxyOptions{BaseDir: dir, Supervise: true, EnvoyPath: script, NginxPath: script})}
	t.Cleanup(func() { _ = m.Proxy.stopEnvoy(); _ = m.Proxy.stopNginx() })
	cfg := daemonProxyConfig()
	cfg.Forward.Enabled = true
	result, err := m.ApplyDelivery(context.Background(), deliveryTestMeta(), config.ServicesConfig{Proxy: cfg}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !outcomeFor(t, result, protection.SubsystemForwardProxy).Retryable || outcomeFor(t, result, protection.SubsystemReverseProxy).Acknowledged == nil {
		t.Fatalf("wrong split outcome: %+v", result.Outcomes)
	}
	pid := m.Proxy.Status()["nginx_pid"]
	if err := os.Rename(fail, fail+".recovered"); err != nil {
		t.Fatal(err)
	}
	result, err = m.RetryDelivery(context.Background(), deliveryTestMeta())
	if err != nil || outcomeFor(t, result, protection.SubsystemForwardProxy).Acknowledged == nil {
		t.Fatalf("retry failed: %+v %v", result, err)
	}
	if m.Proxy.Status()["nginx_pid"] != pid || outcomeFor(t, result, protection.SubsystemReverseProxy).Attempt != 1 {
		t.Fatal("healthy reverse proxy restarted")
	}
}

func TestAVDeliveryUsesSupervisorReadiness(t *testing.T) {
	s := startReadinessICAP(t, "127.0.0.1:0", healthyReadinessReply)
	m := newTestAVManager(t, AVOptions{})
	out, err := m.ApplyDelivery(applyCtx(t), deliveryTestMeta(), readinessICAPConfig(s))
	if err != nil || out.Acknowledged == nil {
		t.Fatalf("initial AV: %+v %v", out, err)
	}
	addr := s.ln.Addr().String()
	s.stop()
	waitAVReady(t, m, false)
	if out := m.DeliveryOutcome(); out.Acknowledged != nil || !out.Retryable {
		t.Fatalf("scanner loss retained proof: %+v", out)
	}
	startReadinessICAP(t, addr, healthyReadinessReply)
	waitAVReady(t, m, true)
	out, err = m.RetryDelivery(applyCtx(t), deliveryTestMeta())
	if err != nil || out.Acknowledged == nil || out.Attempt != 1 {
		t.Fatalf("existing supervisor recovery replayed backend: %+v %v", out, err)
	}
}

func TestAVDeliveryStopCancelsBeforeWaitingForApply(t *testing.T) {
	m := newTestAVManager(t, AVOptions{})
	m.delivery.mu.Lock()
	stopped := make(chan error, 1)
	go func() { stopped <- m.Stop() }()
	select {
	case <-m.ctx.Done():
	case <-time.After(time.Second):
		m.delivery.mu.Unlock()
		t.Fatal("Stop waited on delivery serialization before cancelling AV")
	}
	m.delivery.mu.Unlock()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Stop did not join")
	}
}
