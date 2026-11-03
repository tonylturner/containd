// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"errors"

	"github.com/tonylturner/containd/pkg/app/convergence"
	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/common/trust"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// An intentionally absent engine can never provide runtime proof. Persistence-
// only confirmation still uses the coordinator's fence and deadline retirement.
type unavailableEngine struct{}

var errEngineUnavailable = errors.New("engine unavailable")

func (unavailableEngine) Observe(context.Context) (convergence.Observation, error) {
	return convergence.Observation{}, errEngineUnavailable
}
func (unavailableEngine) Configure(context.Context, protection.Admission, config.DataPlaneConfig) error {
	return errEngineUnavailable
}
func (unavailableEngine) ConfigureInterfaces(context.Context, protection.Admission, []config.Interface, bool) error {
	return errEngineUnavailable
}
func (unavailableEngine) ConfigureRouting(context.Context, protection.Admission, config.RoutingConfig, bool) error {
	return errEngineUnavailable
}
func (unavailableEngine) ConfigureTrust(context.Context, protection.Admission, trust.Bundle) error {
	return errEngineUnavailable
}
func (unavailableEngine) ConfigureServices(context.Context, protection.Admission, config.ServicesConfig) error {
	return errEngineUnavailable
}
func (unavailableEngine) ApplyRules(context.Context, protection.Admission, rules.Snapshot) error {
	return errEngineUnavailable
}
func (unavailableEngine) Retry(context.Context, protection.Admission) error {
	return errEngineUnavailable
}
