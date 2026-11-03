// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	engineapi "github.com/tonylturner/containd/api/engine"
	"github.com/tonylturner/containd/pkg/app/convergence"
	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/common/trust"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/services"
	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// This engine fake models independent positive owner readback. Calls transport
// admitted input, but only owner() publishes proof. The real engine's selective
// adoption and retry implementations are exercised by its own package tests.
type ledgerEngine struct {
	*mockEngine
	mu        sync.Mutex
	status    dpengine.ProtectionStatus
	inputs    map[protection.SubsystemName]any
	mutations map[protection.SubsystemName]int
	fail      map[protection.SubsystemName]bool
	holdWG    bool
}

func newLedgerEngine() *ledgerEngine {
	return &ledgerEngine{mockEngine: &mockEngine{}, status: dpengine.ProtectionStatus{BootID: "boot"},
		inputs: map[protection.SubsystemName]any{}, mutations: map[protection.SubsystemName]int{},
		fail: map[protection.SubsystemName]bool{}}
}

// Caller holds mu. An unchanged input is adopted only after this fake owner's
// readback succeeds. A failure revokes any earlier acknowledgement.
func (e *ledgerEngine) owner(m protection.Metadata, name protection.SubsystemName, input any, stop bool) {
	if !reflect.DeepEqual(e.inputs[name], input) {
		e.inputs[name] = input
		e.mutations[name]++
	}
	op, state := protection.OperationApply, protection.DeliveryReady
	if stop {
		op, state = protection.OperationStop, protection.DeliveryOff
	}
	owner := protection.OwnerEngine
	if name == protection.SubsystemAV {
		owner = protection.OwnerManagement
	}
	out := protection.OwnerOutcome{Name: name, Owner: owner, DesiredRevision: m.RunningRevision,
		Operation: op, State: state, ObservedAt: time.Now().UTC(),
		Acknowledged: &protection.Acknowledgement{Metadata: m, Operation: op}}
	if name == protection.SubsystemTrust {
		out.Acknowledged.TrustRevision = protection.TrustRevision(input.(trust.Bundle).Revision)
	}
	if e.fail[name] {
		out.State, out.Acknowledged, out.Retryable = protection.DeliveryFailed, nil, true
		out.Fault = &protection.Fault{Kind: protection.FaultDelivery, Reason: "owner delivery failed"}
	}
	if e.holdWG && name == protection.SubsystemWireGuard {
		out.State, out.Acknowledged = protection.DeliveryPending, nil
	}
	for i, previous := range e.status.Subsystems {
		if previous.Name == name {
			e.status.Subsystems[i] = out
			return
		}
	}
	e.status.Subsystems = append(e.status.Subsystems, out)
}

func (e *ledgerEngine) admitted(a protection.Admission) {
	e.status.ApplyID, e.status.RunningRevision, e.status.Mode = string(a.ApplyID), a.RunningRevision, a.Mode
	e.status.ObservedAt = time.Now().UTC()
}
func (e *ledgerEngine) ConfigureInterfaces(_ context.Context, a protection.Admission, input []config.Interface, _ bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.admitted(a)
	e.owner(a.Metadata, protection.SubsystemInterfaces, input, false)
	e.owner(a.Metadata, protection.SubsystemForwarding, true, false)
	return nil
}
func (e *ledgerEngine) ConfigureRouting(_ context.Context, a protection.Admission, input config.RoutingConfig, _ bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.owner(a.Metadata, protection.SubsystemRouting, input, false)
	return nil
}
func (e *ledgerEngine) ConfigureTrust(_ context.Context, a protection.Admission, input trust.Bundle) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.owner(a.Metadata, protection.SubsystemTrust, input, false)
	return nil
}
func (e *ledgerEngine) ConfigureServices(_ context.Context, a protection.Admission, input config.ServicesConfig) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.owner(a.Metadata, protection.SubsystemAV, input.AV, !input.AV.Enabled)
	e.owner(a.Metadata, protection.SubsystemWireGuard, input.VPN.WireGuard, !input.VPN.WireGuard.Enabled)
	e.owner(a.Metadata, protection.SubsystemDHCP, input.DHCP, !input.DHCP.Enabled)
	return nil
}
func (e *ledgerEngine) Configure(_ context.Context, a protection.Admission, input config.DataPlaneConfig) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.owner(a.Metadata, protection.SubsystemConfig, input, false)
	e.status.State = "protecting"
	return nil
}
func (e *ledgerEngine) ApplyRules(_ context.Context, a protection.Admission, input rules.Snapshot) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.owner(a.Metadata, protection.SubsystemNFT, input, false)
	e.status.Installed = &protection.Acknowledgement{Metadata: a.Metadata, Operation: protection.OperationApply}
	e.status.InstalledApplyID = string(a.ApplyID)
	return nil
}
func (e *ledgerEngine) RuntimeHealth(context.Context) (engineapi.RuntimeHealth, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.status
	st.Subsystems = append([]protection.OwnerOutcome(nil), st.Subsystems...)
	return engineapi.RuntimeHealth{BootID: "boot", Protection: st}, nil
}
func (e *ledgerEngine) Observe(ctx context.Context) (convergence.Observation, error) {
	health, err := e.RuntimeHealth(ctx)
	return convergence.Observation{BootID: "boot", Engine: health.Protection.Observation(), Outcomes: health.Protection.Subsystems}, err
}
func (e *ledgerEngine) Retry(_ context.Context, a protection.Admission) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, out := range append([]protection.OwnerOutcome(nil), e.status.Subsystems...) {
		if out.Retryable {
			if !e.fail[out.Name] {
				// Count the repaired owner's runtime work, not unrelated services.
				e.mutations[out.Name]++
			}
			e.owner(a.Metadata, out.Name, e.inputs[out.Name], out.Operation == protection.OperationStop)
		}
	}
	return nil
}

func integrationStore(t *testing.T) *config.SQLiteStore {
	t.Helper()
	store := stageStore(t)
	cfg, err := store.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cfg.DataPlane.Enforcement = true
	if err := store.Save(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	return store
}

func integrationManager(t *testing.T) *services.Manager {
	t.Helper()
	return services.NewManager(services.ManagerOptions{BaseDir: t.TempDir()})
}

func integrationStatus(t *testing.T, c convergence.Coordinator, ready bool) protection.Aggregate {
	t.Helper()
	status, err := c.Status(context.Background())
	if err != nil || status.Ready != ready {
		t.Fatalf("ready want %v: %+v error=%v", ready, status, err)
	}
	return status
}

func TestPublicCommitRequiresOwnerProofAndSelectiveDHCPRetry(t *testing.T) {
	store := integrationStore(t)
	engine, manager := newLedgerEngine(), integrationManager(t)
	engine.holdWG, engine.fail[protection.SubsystemDHCP] = true, true
	c := testCoordinator(t, store, engine, manager)
	server := NewServerWithEngineAndServices(store, nil, engine, manager, nil, c)
	rec := requestStage(t, server, "POST", "/config/commit", nil)
	var body struct {
		RunningRevision string
		Protection      protection.Aggregate
	}
	if json.Unmarshal(rec.Body.Bytes(), &body) != nil || rec.Code != 200 || body.Protection.Ready {
		t.Fatalf("transport accepted without proof: %d %s", rec.Code, rec.Body)
	}
	integrationStatus(t, c, false)
	engine.mu.Lock()
	engine.holdWG = false
	meta := engine.status.Installed.Metadata
	engine.owner(meta, protection.SubsystemWireGuard, engine.inputs[protection.SubsystemWireGuard], true)
	engine.mu.Unlock()
	status := integrationStatus(t, c, true)
	if status.ProtectingRevision == nil || string(*status.ProtectingRevision) != body.RunningRevision {
		t.Fatalf("not the committed generation: %+v", status)
	}
	before := make(map[protection.SubsystemName]int)
	engine.mu.Lock()
	for name, count := range engine.mutations {
		before[name] = count
	}
	engine.fail[protection.SubsystemDHCP] = false
	engine.mu.Unlock()
	if err := c.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	integrationStatus(t, c, true)
	for name, count := range engine.mutations {
		want := before[name]
		if name == protection.SubsystemDHCP {
			want++
		}
		if count != want {
			t.Fatalf("DHCP retry mutated %s: %d want %d", name, count, want)
		}
	}
}

func TestManagementRestartAdoptsEngineOwnersAndReconcilesLocalOwners(t *testing.T) {
	store, engine := integrationStore(t), newLedgerEngine()
	first := testCoordinator(t, store, engine, integrationManager(t))
	if err := first.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	integrationStatus(t, first, true)
	old := engine.status.Installed.Metadata
	counts := make(map[protection.SubsystemName]int)
	for name, count := range engine.mutations {
		counts[name] = count
	}
	// New management owners have no inherited proof, even for desired-off.
	local := integrationManager(t)
	restarted := testCoordinator(t, store, engine, local)
	integrationStatus(t, restarted, false)
	if err := restarted.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	integrationStatus(t, restarted, true)
	if engine.status.Installed.ApplyID == old.ApplyID || !reflect.DeepEqual(counts, engine.mutations) {
		t.Fatalf("unchanged engine owners restarted: %v -> %v", counts, engine.mutations)
	}
	for _, outcome := range local.DeliveryOutcomes() {
		if outcome.Name == protection.SubsystemForwardProxy || outcome.Name == protection.SubsystemReverseProxy || outcome.Name == protection.SubsystemOpenVPN {
			if outcome.Acknowledged == nil || outcome.Acknowledged.ApplyID == old.ApplyID || outcome.Operation != protection.OperationStop {
				t.Fatalf("unproven local teardown: %+v", outcome)
			}
		}
	}
}

func TestWireGuardAndProxyFaultsGatePublicProtection(t *testing.T) {
	for _, name := range []protection.SubsystemName{protection.SubsystemWireGuard, protection.SubsystemReverseProxy} {
		t.Run(string(name), func(t *testing.T) {
			store, engine := integrationStore(t), newLedgerEngine()
			if name == protection.SubsystemWireGuard {
				engine.fail[name] = true
			} else {
				cfg, err := store.Load(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				cfg.Services.Proxy.Reverse = config.ReverseProxyConfig{Enabled: true, Sites: []config.ReverseProxySite{{
					Name: "missing", ListenPort: 443, Backends: []string{"127.0.0.1:80"}, TLSEnabled: true, CertRef: "missing"}}}
				if err := store.Save(context.Background(), cfg); err != nil {
					t.Fatal(err)
				}
			}
			manager := integrationManager(t)
			manager.Proxy.CertsDir = t.TempDir()
			c := testCoordinator(t, store, engine, manager)
			if err := c.Tick(context.Background()); err != nil {
				t.Fatal(err)
			}
			status := integrationStatus(t, c, false)
			for _, out := range status.Subsystems {
				if out.Name == name && out.Required && out.Fault != nil && out.Acknowledged == nil {
					return
				}
			}
			t.Fatal(errors.New("required fault disappeared"))
		})
	}
}

type changedReadbackEngine struct {
	*ledgerEngine
	reads int
}

func (e *changedReadbackEngine) RuntimeHealth(ctx context.Context) (engineapi.RuntimeHealth, error) {
	h, err := e.ledgerEngine.RuntimeHealth(ctx)
	e.reads++
	if e.reads >= 2 {
		for i := range h.Protection.Subsystems {
			out := &h.Protection.Subsystems[i]
			if out.Name == protection.SubsystemWireGuard {
				out.Acknowledged, out.State = nil, protection.DeliveryFailed
				out.Fault = &protection.Fault{Kind: protection.FaultDelivery, Reason: "owner lost"}
			}
		}
	}
	return h, err
}

func TestProtectionResponseRejectsChangedOwnerProofWithSameIdentity(t *testing.T) {
	engine := &changedReadbackEngine{ledgerEngine: newLedgerEngine()}
	c := testCoordinator(t, integrationStore(t), engine, integrationManager(t))
	if err := c.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	integrationStatus(t, c, true)
	view, err := authenticatedProtection(context.Background(), c, engine)
	if err == nil || view["ready"] != false || view["state"] != protection.StateUnknown {
		t.Fatalf("owner loss hidden behind unchanged identity: %+v %v", view, err)
	}
}
