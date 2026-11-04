// SPDX-License-Identifier: Apache-2.0

package convergence

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/common/trust"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/services"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

type memoryStore struct {
	config.RuntimeStore
	mu                   sync.Mutex
	state                config.RunningState
	notify               chan<- struct{}
	read                 func(context.Context) error
	apply                func(context.Context, func(context.Context, *config.RunningSnapshot, *config.RunningSnapshot) error) error
	rollbacks, completes int
	fault                string
}

func detached(s *config.RunningSnapshot) *config.RunningSnapshot {
	if s == nil {
		return nil
	}
	cfg := *s.Config
	next := *s
	next.Config = &cfg
	if next.PendingConfirm != nil {
		p := *next.PendingConfirm
		next.PendingConfirm = &p
	}
	return &next
}

func (s *memoryStore) ReadRunning(ctx context.Context) (config.RunningState, error) {
	if s.read != nil {
		if err := s.read(ctx); err != nil {
			return config.RunningState{}, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.state
	state.Running = detached(state.Running)
	if state.Transition != nil {
		g := *state.Transition
		state.Transition = &g
	}
	return state, nil
}

func (s *memoryStore) ApplyChange(ctx context.Context, _ config.Revision, _ config.RunningChange, _ time.Duration, apply func(context.Context, *config.RunningSnapshot, *config.RunningSnapshot) error) (config.Revision, error) {
	if s.apply == nil {
		return "", errors.New("unexpected transition")
	}
	err := s.apply(ctx, apply)
	return "cas-after", err
}

func (s *memoryStore) ApplyReset(ctx context.Context, r config.Revision, _ *config.Config, apply func(context.Context, *config.RunningSnapshot, *config.RunningSnapshot) error) (config.Revision, error) {
	return s.ApplyChange(ctx, r, config.ChangeCommit, 0, apply)
}

func (s *memoryStore) Rollback(ctx context.Context, expected config.Revision) (config.Revision, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Revision != expected {
		return "", &config.ErrRevisionMismatch{}
	}
	s.rollbacks++
	s.state.Running = detached(s.state.Running)
	s.state.Running.RunningRevision = config.RunningRevision(string(s.state.Running.RunningRevision) + "_restored")
	s.state.Running.PendingConfirm = nil
	s.state.Transition = &config.TransitionGuard{ID: "rollback", State: config.TransitionReapplyPending, RunningRevision: s.state.Running.RunningRevision}
	return s.state.Revision, nil
}

func (s *memoryStore) ConfirmCommit(_ context.Context, _ config.Revision) (config.Revision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Running = detached(s.state.Running)
	s.state.Running.PendingConfirm = nil
	return s.state.Revision, nil
}

func (s *memoryStore) CompleteRuntimeApply(_ context.Context, target config.RunningRevision, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Running.RunningRevision != target || s.state.Transition != nil && s.state.Transition.ID != id {
		return config.ErrTransitionMismatch
	}
	s.completes++
	s.state.Transition = nil
	s.fault = ""
	return nil
}

func (s *memoryStore) RuntimeApplyFault(context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fault, nil
}

func (s *memoryStore) SetRuntimeApplyFault(_ context.Context, target config.RunningRevision, fault string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Running.RunningRevision != target {
		return config.ErrTransitionMismatch
	}
	s.fault = fault
	return nil
}

func (s *memoryStore) SetStoreNotify(ch chan<- struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.notify = ch
}

type fakeEngine struct {
	mu          sync.Mutex
	observation Observation
	calls       map[string]int
	fail        map[string]int
	hook        func(context.Context, string) error
}

func (e *fakeEngine) Observe(context.Context) (Observation, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	o := e.observation
	o.Outcomes = cloneOutcomes(o.Outcomes)
	if o.Engine.Installed != nil {
		a := *o.Engine.Installed
		o.Engine.Installed = &a
	}
	return o, nil
}

func proof(m protection.Metadata, name protection.SubsystemName, owner protection.Owner, stop bool) protection.OwnerOutcome {
	op, state := protection.OperationApply, protection.DeliveryReady
	if stop {
		op, state = protection.OperationStop, protection.DeliveryOff
	}
	return protection.OwnerOutcome{Name: name, Owner: owner, DesiredRevision: m.RunningRevision, Operation: op,
		State: state, ObservedAt: time.Now().UTC(), Acknowledged: &protection.Acknowledgement{Metadata: m, Operation: op}}
}

func (e *fakeEngine) phase(ctx context.Context, a protection.Admission, name string, outcomes ...protection.OwnerOutcome) error {
	if e.hook != nil {
		if err := e.hook(ctx, name); err != nil {
			return err
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls[name]++
	e.observation.Engine.Metadata = a.Metadata
	e.observation.Engine.ObservedAt = time.Now().UTC()
	if e.fail[name] > 0 {
		e.fail[name]--
		return errors.New("delivery failed")
	}
	for _, o := range outcomes {
		e.observation.Outcomes = replace(e.observation.Outcomes, o)
	}
	return nil
}

func (e *fakeEngine) ConfigureInterfaces(ctx context.Context, a protection.Admission, _ []config.Interface, replace bool) error {
	name := "interfaces"
	if replace {
		name += "-replace"
	}
	return e.phase(ctx, a, name, proof(a.Metadata, protection.SubsystemInterfaces, protection.OwnerEngine, false))
}
func (e *fakeEngine) ConfigureRouting(ctx context.Context, a protection.Admission, _ config.RoutingConfig, replace bool) error {
	name := "routing"
	if replace {
		name += "-replace"
	}
	return e.phase(ctx, a, name, proof(a.Metadata, protection.SubsystemRouting, protection.OwnerEngine, false))
}
func (e *fakeEngine) ConfigureTrust(ctx context.Context, a protection.Admission, b trust.Bundle) error {
	o := proof(a.Metadata, protection.SubsystemTrust, protection.OwnerEngine, false)
	o.Acknowledged.TrustRevision = protection.TrustRevision(b.Revision)
	return e.phase(ctx, a, "trust", o)
}
func (e *fakeEngine) ConfigureServices(ctx context.Context, a protection.Admission, _ config.ServicesConfig) error {
	return e.phase(ctx, a, "services", proof(a.Metadata, protection.SubsystemAV, protection.OwnerManagement, true),
		proof(a.Metadata, protection.SubsystemWireGuard, protection.OwnerEngine, true),
		proof(a.Metadata, protection.SubsystemDHCP, protection.OwnerEngine, true))
}
func (e *fakeEngine) Configure(ctx context.Context, a protection.Admission, dp config.DataPlaneConfig) error {
	if err := e.phase(ctx, a, "config", proof(a.Metadata, protection.SubsystemConfig, protection.OwnerEngine, false)); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.observation.Engine.State = protection.StateProtecting
	if !dp.Enforcement {
		e.observation.Engine.State = protection.StateDisabled
	}
	return nil
}
func (e *fakeEngine) ApplyRules(ctx context.Context, a protection.Admission, _ rules.Snapshot) error {
	o := proof(a.Metadata, protection.SubsystemNFT, protection.OwnerEngine, false)
	if err := e.phase(ctx, a, "nft", o); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.observation.Engine.Installed = o.Acknowledged
	return nil
}
func (e *fakeEngine) Retry(ctx context.Context, a protection.Admission) error {
	return e.phase(ctx, a, "retry")
}
func (e *fakeEngine) count(name string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.calls[name]
}

type fakeServices struct {
	mu                     sync.Mutex
	meta                   protection.Metadata
	effective              config.ServicesConfig
	outcomes               []protection.OwnerOutcome
	failed                 protection.SubsystemName
	quarantine             bool
	applyCount, retryCount int
}

func (s *fakeServices) ApplyDelivery(_ context.Context, m protection.Metadata, cfg config.ServicesConfig, faults []config.ServiceConfigError) (services.DeliveryResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.meta, s.effective = m, cfg
	for _, f := range faults {
		config.QuarantineService(&s.effective, f.Service)
	}
	s.applyCount++
	s.outcomes = nil
	for _, name := range []protection.SubsystemName{protection.SubsystemOpenVPN, protection.SubsystemForwardProxy,
		protection.SubsystemReverseProxy, protection.SubsystemDNS, protection.SubsystemNTP, protection.SubsystemSyslog} {
		o := proof(m, name, protection.OwnerManagement, true)
		if name == s.failed {
			o.State, o.Acknowledged, o.Retryable = protection.DeliveryFailed, nil, true
			o.Fault = &protection.Fault{Kind: protection.FaultDelivery, Reason: "owner stop failed"}
		}
		s.outcomes = append(s.outcomes, o)
	}
	return s.result(), nil
}
func (s *fakeServices) result() services.DeliveryResult {
	effective := s.effective
	if s.quarantine {
		effective.Proxy.Forward.Enabled = false
	}
	return services.DeliveryResult{Effective: effective, Outcomes: cloneOutcomes(s.outcomes)}
}
func (s *fakeServices) RetryDelivery(_ context.Context, m protection.Metadata) (services.DeliveryResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.meta != m {
		return services.DeliveryResult{}, services.ErrDeliverySuperseded
	}
	s.retryCount++
	for i, o := range s.outcomes {
		if o.Retryable && s.failed == "" {
			s.outcomes[i] = proof(m, o.Name, protection.OwnerManagement, true)
		}
	}
	return s.result(), nil
}
func (s *fakeServices) DeliveryOutcomes() []protection.OwnerOutcome {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneOutcomes(s.outcomes)
}

type fakeEnvironment struct {
	mu               sync.Mutex
	recovery         bool
	refreshes, pcaps int
}

func (e *fakeEnvironment) Prepare(_ context.Context, s *config.RunningSnapshot) (Prepared, error) {
	effective, faults, err := config.Effective(s.Config, nil)
	return Prepared{Effective: effective, Faults: faults, Trust: trust.Bundle{Revision: trust.NoRevision}}, err
}
func (e *fakeEnvironment) Recovery(_ context.Context, state config.RunningState) (RecoveryPlan, bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	recovery := e.recovery || state.Transition != nil && state.Transition.State != config.TransitionReapplyPending
	return RecoveryPlan{Rules: rules.Snapshot{Version: config.ManagementRecoveryVersion, Default: rules.ActionDeny},
		Addresses: []config.Interface{{Name: "mgmt", Addresses: []string{"192.0.2.1/24"}}}}, recovery, nil
}
func (e *fakeEnvironment) Refresh(context.Context, *config.RunningSnapshot) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.refreshes++
	return nil
}
func (e *fakeEnvironment) SavedPCAP(context.Context, *config.RunningSnapshot, *config.RunningSnapshot) []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.pcaps++
	return []string{"pcap unavailable"}
}

type fakeDemo struct {
	mu                         sync.Mutex
	synced, reconciles, resets int
}

func (d *fakeDemo) Reset(context.Context) { d.mu.Lock(); defer d.mu.Unlock(); d.resets++ }
func (d *fakeDemo) EngineSynced(context.Context, string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.synced++
}
func (d *fakeDemo) Reconcile(context.Context) { d.mu.Lock(); defer d.mu.Unlock(); d.reconciles++ }
func (d *fakeDemo) counts() (int, int, int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.synced, d.reconciles, d.resets
}

func fixture(t *testing.T) (*coordinator, *memoryStore, *fakeEngine, *fakeServices, *fakeEnvironment, *fakeDemo) {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.DataPlane.Enforcement = true
	cfg.Services = config.ServicesConfig{}
	store := &memoryStore{state: config.RunningState{Revision: "cas", Running: &config.RunningSnapshot{Config: cfg, RunningRevision: "running"}}}
	engine := &fakeEngine{observation: Observation{BootID: "boot"}, calls: map[string]int{}, fail: map[string]int{}}
	local, env, demo := &fakeServices{}, &fakeEnvironment{}, &fakeDemo{}
	co, err := New(Options{Store: store, Engine: engine, Services: local, Environment: env, Demo: demo})
	if err != nil {
		t.Fatal(err)
	}
	return co.(*coordinator), store, engine, local, env, demo
}

func tick(t *testing.T, c Coordinator) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.Tick(ctx); err != nil {
		t.Fatal(err)
	}
}

func ready(t *testing.T, c Coordinator, want bool) protection.Aggregate {
	t.Helper()
	got, err := c.Status(context.Background())
	if err != nil || got.Ready != want {
		t.Fatalf("ready=%v want=%v err=%v aggregate=%+v", got.Ready, want, err, got)
	}
	return got
}
