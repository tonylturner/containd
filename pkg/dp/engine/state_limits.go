// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"fmt"

	"github.com/tonylturner/containd/pkg/common/metrics"
	"github.com/tonylturner/containd/pkg/dp/limits"
)

func (e *Engine) inspectionResources() limits.Resources {
	return limits.NewResources(e.budget, e.ledger)
}

// initStateLimits is shared by live and detached constructors. Operator bounds
// belong to configuration validation, not to internal test/offline injection.
func (e *Engine) initStateLimits(l limits.Limits, ledger *limits.Ledger) error {
	if l.MaxFlows < 0 || l.MaxTopTalkers < 0 || l.MaxInspectionBytes < 0 {
		return fmt.Errorf("engine limits must not be negative")
	}
	defaults := limits.Default()
	if l.MaxFlows == 0 {
		l.MaxFlows = defaults.MaxFlows
	}
	if l.MaxTopTalkers == 0 {
		l.MaxTopTalkers = defaults.MaxTopTalkers
	}
	if l.MaxInspectionBytes == 0 {
		l.MaxInspectionBytes = defaults.MaxInspectionBytes
	}
	if ledger == nil {
		ledger = limits.NewLedger(nil)
	}
	e.stateLimits, e.budget, e.ledger = l, limits.NewBudget(l.MaxInspectionBytes), ledger
	e.stats.SetLimits(l, e.budget, ledger)
	e.anomalyDetector.SetLimits(l, e.budget, ledger)
	e.sigEngine.SetLimits(l, e.budget, ledger)
	e.inventory.SetLimits(l, e.budget, ledger)
	e.verdictCache.ledger = ledger
	e.conformance.ledger = ledger
	return nil
}

// Ledger is shared by successive live configurations; detached engines keep a
// private ledger and never register it with process telemetry.
func (e *Engine) Ledger() *limits.Ledger {
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	return e.ledger
}

// LimitOccupancy reports reserved directional slots, including unseen peers.
func (e *Engine) LimitOccupancy() limits.Occupancy {
	e.flowMu.Lock()
	defer e.flowMu.Unlock()
	return limits.Occupancy{Limit: int64(e.stateLimits.MaxFlows), Entries: int64(e.flowSlots), HighWater: int64(e.flowHighWater)}
}
func (e *Engine) syncFlowsActiveLocked() {
	if !e.detached {
		metrics.FlowsActive.Set(float64(len(e.flows)))
	}
}

// StateLimits samples the current configuration's owners while replacement is
// excluded. Owner-local locks protect their individual occupancy samples.
func (e *Engine) StateLimits() limits.Snapshot {
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	return e.stateLimitsSnapshot()
}

// Caller excludes owner replacement through lifecycleMu or the joined run lifetime.
func (e *Engine) stateLimitsSnapshot() limits.Snapshot {
	e.policyMu.RLock()
	defer e.policyMu.RUnlock()
	s := limits.Snapshot{Tables: []limits.TableStatus{}, Budget: e.budget.Status()}
	add := func(t limits.Table, o limits.Occupancy) { s.Tables = append(s.Tables, e.ledger.Status(t, o)) }
	add(limits.TableFlows, e.LimitOccupancy())
	add(limits.TableInspection, limits.Occupancy{Limit: s.Budget.Limit, ChargedBytes: s.Budget.InUse, HighWater: s.Budget.HighWater})
	add(limits.TableTopTalkers, e.stats.LimitOccupancy())
	add(limits.TableRateTrackers, e.anomalyDetector.LimitOccupancy())
	add(limits.TableIECSessions, e.sessions.LimitOccupancy())
	add(limits.TableIECReconnect, e.sessions.reconnectLimitOccupancy())
	add(limits.TableInventoryPoints, e.inventory.LimitOccupancy())
	add(limits.TableSignatureWindows, e.sigEngine.LimitOccupancy())
	add(limits.TableConformance, e.conformance.LimitOccupancy())
	add(limits.TableVerdictCache, e.verdictCache.LimitOccupancy())
	add(limits.TablePickupReset, e.sessions.pickups.LimitOccupancy())
	// Only the legacy manager registers HTTP decoders today.
	add(limits.TableHTTPCorrelation, e.httpCorrelationOccupancy())
	return s
}
