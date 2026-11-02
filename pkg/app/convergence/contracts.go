// SPDX-License-Identifier: Apache-2.0

// Package convergence coordinates delivery of running intent. Runtime owners
// retain their own supervision and acknowledgement authority.
package convergence

import (
	"context"
	"errors"
	"time"

	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/common/trust"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/services"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

var (
	ErrSuperseded = errors.New("convergence target superseded")
	ErrUncertain  = errors.New("runtime uncertain; explicit resolution required")
	ErrDrain      = errors.New("runtime worker did not drain; overlapping effects refused")
	// Adapters map engine apply_input_changed/predecessor/boot conflicts to
	// this sentinel so the next observation can create a fresh admitted target.
	ErrInputChanged = errors.New("resolved engine input or admission changed")
)

const (
	RetryBudget = 5 * time.Second
	ApplyBudget = 30 * time.Second
)

// EngineClient adapters attach Admission to EVERY mutating request, including
// retries and explicit replace. Observe projects the existing protection status;
// it must not manufacture an acknowledgement from HTTP success.
type EngineClient interface {
	Observe(context.Context) (Observation, error)
	ConfigureInterfaces(context.Context, protection.Admission, []config.Interface, bool) error
	ConfigureRouting(context.Context, protection.Admission, config.RoutingConfig, bool) error
	ConfigureTrust(context.Context, protection.Admission, trust.Bundle) error
	ConfigureServices(context.Context, protection.Admission, config.ServicesConfig) error
	Configure(context.Context, protection.Admission, config.DataPlaneConfig) error
	ApplyRules(context.Context, protection.Admission, rules.Snapshot) error
	Retry(context.Context, protection.Admission) error
}

type Observation struct {
	// BootID is outer health authority, even before the first admitted attempt.
	BootID    protection.BootID
	Engine    protection.EngineObservation
	Outcomes  []protection.OwnerOutcome
	Degraded  bool
	Retryable bool
}

// ServiceApplier is implemented directly by services.Manager.
type ServiceApplier interface {
	ApplyDelivery(context.Context, protection.Metadata, config.ServicesConfig, []config.ServiceConfigError) (services.DeliveryResult, error)
	RetryDelivery(context.Context, protection.Metadata) (services.DeliveryResult, error)
	DeliveryOutcomes() []protection.OwnerOutcome
}

// Prepared contains detached inputs. Selection MUST be derived from the original
// desired policy before any quarantine. Effective includes validated device
// resolution, never persisted over running. Trust uses the existing bundle
// revision, not a new material-provenance system.
type Prepared struct {
	Effective *config.Config
	Faults    []config.ServiceConfigError
	Selection protection.Selection
	Trust     trust.Bundle
}

type RecoveryPlan struct {
	Rules     rules.Snapshot
	Addresses []config.Interface
}

// Environment owns assembly-specific reservation, boot-refusal, device discovery
// and material access. Prepare/Recovery are read-only and never read Store during
// synchronous callbacks. Refresh explicitly revalidates/reloads referenced
// material on SIGHUP, even when JSON and process liveness have not changed.
// SavedPCAP is one-shot, outside the retry ledger; warnings never gate ready.
type Environment interface {
	Prepare(context.Context, *config.RunningSnapshot) (Prepared, error)
	Recovery(context.Context, config.RunningState) (RecoveryPlan, bool, error)
	Refresh(context.Context, *config.RunningSnapshot) error
	SavedPCAP(context.Context, *config.RunningSnapshot, *config.RunningSnapshot) []string
}

// DemoHooks must be idempotent. Reset retires synced eligibility before a new
// boot, recovery or invalidated baseline can reconcile user preferences.
type DemoHooks interface {
	Reset(context.Context)
	EngineSynced(context.Context, string)
	Reconcile(context.Context)
}

type Options struct {
	Store       config.RuntimeStore
	Engine      EngineClient
	Services    ServiceApplier
	Environment Environment
	Demo        DemoHooks
	// Errors is an optional nonblocking, coalescing diagnostics sink. Delivery
	// authority always remains the labelled ledger and live Status.
	Errors chan<- error
}

type Result struct {
	Revision        config.Revision
	RunningRevision config.RunningRevision
	ApplyID         protection.ApplyID
	Warnings        []string
}

// Coordinator is the sole management transition fence. Run is called once;
// cancellation joins all work before returning (or reports ErrDrain without
// allowing any overlapping effects). Tick is useful for headless deterministic
// driving when Run is not active. Status collects coherent current authority,
// not a cached ready bit. Retry is a fenced, coalescing request, not resolution.
type Coordinator interface {
	Run(context.Context) error
	Tick(context.Context) error
	Status(context.Context) (protection.Aggregate, error)
	Change(context.Context, config.Revision, config.RunningChange, time.Duration) (Result, error)
	Confirm(context.Context, config.Revision) (config.Revision, error)
	Reset(context.Context, config.Revision, *config.Config) (Result, error)
	Replay(context.Context, bool) (Result, error)
	TrustChanged(context.Context, func(context.Context, *config.RunningSnapshot) error) (Result, error)
	Reconcile(context.Context, protection.SubsystemName) error
	Retry(protection.Metadata) error
}
