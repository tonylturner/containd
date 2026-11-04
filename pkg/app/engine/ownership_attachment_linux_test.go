// SPDX-License-Identifier: Apache-2.0
//go:build linux

package engineapp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/app/convergence"
	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/common/trust"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/services"
	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"go.uber.org/zap"
)

// Keep interface HTTP delivery, ownership maintenance, policy installation and
// management convergence real. Unrelated routing/services/storage are inert
// owners with explicit proofs, so no host daemons or routes are changed.
type attachmentDeliveryFixture struct {
	config.RuntimeStore
	convergence.Environment
	state    config.RunningState
	dp       *engine.Engine
	owner    *ownershipManager
	protocol *protectionCoordinator
	local    []protection.OwnerOutcome
	calls    map[string]int
	fault    string
}

func (f *attachmentDeliveryFixture) ReadRunning(context.Context) (config.RunningState, error) {
	return f.state, nil
}
func (f *attachmentDeliveryFixture) RuntimeApplyFault(context.Context) (string, error) {
	return f.fault, nil
}
func (f *attachmentDeliveryFixture) SetRuntimeApplyFault(_ context.Context, _ config.RunningRevision, fault string) error {
	f.fault = fault
	return nil
}
func (f *attachmentDeliveryFixture) CompleteRuntimeApply(context.Context, config.RunningRevision, string) error {
	return nil
}
func (f *attachmentDeliveryFixture) Prepare(_ context.Context, s *config.RunningSnapshot) (convergence.Prepared, error) {
	return convergence.Prepared{Effective: s.Config, Trust: trust.Bundle{Revision: trust.NoRevision}}, nil
}
func (f *attachmentDeliveryFixture) Recovery(context.Context, config.RunningState) (convergence.RecoveryPlan, bool, error) {
	return convergence.RecoveryPlan{}, false, nil
}
func (f *attachmentDeliveryFixture) SavedPCAP(context.Context, *config.RunningSnapshot, *config.RunningSnapshot) []string {
	return nil
}

func attachmentProof(m protection.Metadata, name protection.SubsystemName, owner protection.Owner) protection.OwnerOutcome {
	return protection.OwnerOutcome{Name: name, Owner: owner, DesiredRevision: m.RunningRevision,
		Operation: protection.OperationApply, State: protection.DeliveryReady, ObservedAt: time.Now().UTC(),
		Acknowledged: &protection.Acknowledgement{Metadata: m, Operation: protection.OperationApply}}
}

func (f *attachmentDeliveryFixture) ApplyDelivery(_ context.Context, m protection.Metadata, cfg config.ServicesConfig, _ []config.ServiceConfigError) (services.DeliveryResult, error) {
	f.local = nil
	for _, row := range protection.Requirements(protection.Selection{}) {
		if row.Owner == protection.OwnerManagement {
			f.local = append(f.local, attachmentProof(m, row.Name, row.Owner))
		}
	}
	return services.DeliveryResult{Effective: cfg, Outcomes: f.local}, nil
}
func (f *attachmentDeliveryFixture) RetryDelivery(context.Context, protection.Metadata) (services.DeliveryResult, error) {
	return services.DeliveryResult{Effective: f.state.Running.Services, Outcomes: f.local}, nil
}
func (f *attachmentDeliveryFixture) DeliveryOutcomes() []protection.OwnerOutcome { return f.local }

func (f *attachmentDeliveryFixture) Observe(context.Context) (convergence.Observation, error) {
	st := f.dp.Protection()
	return convergence.Observation{BootID: protection.BootID(st.BootID), Engine: st.Observation(),
		Outcomes: st.Subsystems, Retryable: st.Retryable}, nil
}
func (f *attachmentDeliveryFixture) ConfigureInterfaces(_ context.Context, a protection.Admission, ifaces []config.Interface, _ bool) error {
	f.calls["interfaces"]++
	body, err := json.Marshal(ifaces)
	if err != nil {
		return err
	}
	h := f.protocol.admit("interfaces", interfacesHandler(zap.NewNop().Sugar(), f.owner))
	w := protocolPost(h, a.Metadata, string(a.PreviousApplyID), string(body))
	if w.Code != http.StatusOK {
		return fmt.Errorf("interface delivery: %d %s", w.Code, w.Body)
	}
	return nil
}
func (f *attachmentDeliveryFixture) acknowledge(m protection.Metadata, name protection.SubsystemName) {
	f.dp.SetProtectionOutcome(m, attachmentProof(m, name, protection.OwnerEngine))
}
func (f *attachmentDeliveryFixture) ConfigureRouting(_ context.Context, a protection.Admission, _ config.RoutingConfig, _ bool) error {
	f.acknowledge(a.Metadata, protection.SubsystemRouting)
	return nil
}
func (f *attachmentDeliveryFixture) ConfigureTrust(_ context.Context, a protection.Admission, b trust.Bundle) error {
	out := attachmentProof(a.Metadata, protection.SubsystemTrust, protection.OwnerEngine)
	out.Acknowledged.TrustRevision = protection.TrustRevision(b.Revision)
	f.dp.SetProtectionOutcome(a.Metadata, out)
	return nil
}
func (f *attachmentDeliveryFixture) ConfigureServices(_ context.Context, a protection.Admission, _ config.ServicesConfig) error {
	for _, name := range []protection.SubsystemName{protection.SubsystemAV, protection.SubsystemWireGuard, protection.SubsystemDHCP} {
		out := attachmentProof(a.Metadata, name, protection.OwnerEngine)
		if name == protection.SubsystemAV {
			out.Owner = protection.OwnerManagement
		}
		f.dp.SetProtectionOutcome(a.Metadata, out)
	}
	return nil
}
func (f *attachmentDeliveryFixture) Configure(_ context.Context, a protection.Admission, _ config.DataPlaneConfig) error {
	f.acknowledge(a.Metadata, protection.SubsystemConfig)
	return nil
}
func (f *attachmentDeliveryFixture) ApplyRules(_ context.Context, a protection.Admission, snap rules.Snapshot) error {
	f.calls["nft"]++
	h := f.protocol.admit("nft", func(w http.ResponseWriter, r *http.Request) {
		if err := f.dp.ApplyRules(r.Context(), snap); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	})
	w := protocolPost(h, a.Metadata, string(a.PreviousApplyID), "{}")
	if w.Code != http.StatusOK {
		return fmt.Errorf("rule delivery: %d %s", w.Code, w.Body)
	}
	return nil
}
func (f *attachmentDeliveryFixture) Retry(context.Context, protection.Admission) error {
	f.calls["retry"]++
	return nil
}

func TestOwnershipAttachmentDoesNotRedeliver(t *testing.T) {
	if os.Getenv("CONTAIND_NETNS_KERNEL_TEST") != "1" {
		t.Skip("requires disposable Linux container")
	}
	t.Setenv("CONTAIND_ADDRESS_STATE_PATH", filepath.Join(t.TempDir(), "addresses.json"))
	cfg := config.DefaultConfig()
	cfg.DataPlane.Enforcement = true
	cfg.Services = config.ServicesConfig{}
	cfg.Interfaces = []config.Interface{{Name: "lateattach", Zone: "lan", Addresses: []string{"192.0.2.17/24"}}}
	cfg.Firewall.NAT.Enabled = false
	cfg.Firewall.Rules = []config.Rule{{ID: "lan-deny", SourceZones: []string{"lan"}, Action: config.ActionDeny}}
	dp, err := engine.New(engine.Config{Enforce: engine.EnforceConfig{
		Enabled: true, Applier: adoptionApplier{},
		ClearMark: func(context.Context, uint32, uint32, uint32) (int, error) { return 0, nil },
	}})
	if err != nil {
		t.Fatal(err)
	}
	protocol := testProtectionCoordinator(t, dp)
	owner := newOwnershipManager(zap.NewNop().Sugar())
	owner.coordinator, owner.observeAttachment = protocol, dp.ReconcileInterfaceAttachment
	f := &attachmentDeliveryFixture{dp: dp, owner: owner, protocol: protocol, calls: map[string]int{},
		state: config.RunningState{Revision: "cas", Running: &config.RunningSnapshot{Config: cfg, RunningRevision: "running"}}}
	c, err := convergence.New(convergence.Options{Store: f, Engine: f, Services: f, Environment: f})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for range 3 {
		if err := c.Tick(ctx); err != nil {
			t.Fatal(err)
		}
		owner.reconcile(ctx, "periodic")
		st, err := c.Status(ctx)
		if err != nil || st.State != protection.StateDegraded || st.Ready || f.fault != "" || owner.getLastError() != "" {
			t.Fatalf("attachment became delivery failure: status=%+v error=%v fault=%q owner=%q", st, err, f.fault, owner.getLastError())
		}
		out := subsystem(t, dp.Protection(), protection.SubsystemInterfaces)
		if out.State != protection.DeliveryReady || out.Acknowledged == nil || out.Fault != nil || out.Retryable {
			t.Fatalf("interface acknowledgement revoked: %+v", out)
		}
	}
	if f.calls["interfaces"] != 1 || f.calls["nft"] != 1 || f.calls["retry"] != 0 {
		t.Fatalf("attachment caused redelivery/retry: %v", f.calls)
	}
}
