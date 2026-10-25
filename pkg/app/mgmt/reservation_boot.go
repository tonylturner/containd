// SPDX-License-Identifier: Apache-2.0
package mgmtapp

import (
	"context"
	"errors"
	"fmt"
	"time"

	httpapi "github.com/tonylturner/containd/api/http"
	"github.com/tonylturner/containd/pkg/common"
	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/services"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
	"go.uber.org/zap"
)

// Deployment conflicts remain fatal even when stored config needs recovery.
func validateReservedEnvironment(r *mgmtpath.Reservation) error {
	if r == nil {
		return nil
	}
	if addr := common.EnvTrimmed("CONTAIND_MGMT_ADDR", ""); addr != "" {
		if err := r.ValidateListen(addr); err != nil {
			return fmt.Errorf("CONTAIND_MGMT_ADDR: %w", err)
		}
	}
	httpAddr := common.EnvTrimmed("CONTAIND_MGMT_ADDR", fmt.Sprintf(":%d", r.Port))
	for _, key := range []string{"CONTAIND_MGMT_HTTPS_ADDR", "CONTAIND_SSH_ADDR"} {
		addr := common.EnvTrimmed(key, "")
		conflict := config.ManagementListenerOverlaps(addr, r)
		if key == "CONTAIND_MGMT_HTTPS_ADDR" {
			conflict = config.ManagementListenerConflictsHTTP(addr, httpAddr, true, r)
		}
		if conflict {
			return fmt.Errorf("%s conflicts with reserved management path", key)
		}
	}
	return nil
}

// A disjoint SSH env bind can still collide with a wildcard HTTP socket. Check
// that only once the effective (possibly boot-only) HTTP bind is known.
func validateReservedBootEnvironment(cfg *config.Config, r *mgmtpath.Reservation) error {
	if config.ManagementListenerConflictsHTTP(common.EnvTrimmed("CONTAIND_SSH_ADDR", ""), resolveHTTPAddr(cfg), false, r) {
		return fmt.Errorf("CONTAIND_SSH_ADDR conflicts with reserved management path HTTP socket")
	}
	return nil
}

func reservationBootConflict(cfg *config.Config, r *mgmtpath.Reservation) error {
	return errors.Join(config.ValidateManagementReservation(cfg, r), validateReservedStartup(cfg, r))
}

// Only listeners are replaced, and only in memory. APIs continue to expose the
// stored config so the operator can inspect and fix the actual conflict.
func reservationSafeBootListeners(cfg *config.Config, r *mgmtpath.Reservation) *config.Config {
	if r == nil || cfg == nil {
		return cfg
	}
	if config.ValidateManagementListeners(cfg.System, r) == nil && validateReservedStartup(cfg, r) == nil {
		return cfg
	}
	safe := *cfg
	defaults := httpapi.ApplianceDefaults(r)
	safe.System.Mgmt = defaults.System.Mgmt
	safe.System.SSH.ListenAddr = defaults.System.SSH.ListenAddr
	return &safe
}

func recordReservationBootDecision(logger *zap.SugaredLogger, stores mgmtStores, cfg *config.Config, r *mgmtpath.Reservation) (*dpevents.Event, error) {
	if r == nil {
		return nil, nil
	}
	store, ok := stores.store.(interface {
		SetManagementBootFault(context.Context, string) error
	})
	if !ok {
		return nil, errors.New("config store does not support management boot fault persistence")
	}
	conflict := reservationBootConflict(cfg, r)
	fault := ""
	if conflict != nil {
		fault = conflict.Error()
	}
	ctx := context.Background()
	if err := store.SetManagementBootFault(ctx, fault); err != nil {
		return nil, err
	}
	if conflict == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	const kind = "management.reservation.boot_fault"
	if err := stores.auditStore.Add(ctx, audit.Record{
		Timestamp: now, Actor: "system", Source: "management",
		Action: kind, Result: "fault", Detail: fault,
	}); err != nil {
		return nil, fmt.Errorf("record management boot fault event: %w", err)
	}
	logger.Errorw(kind, "error", fault)
	return &dpevents.Event{ID: uint64(now.UnixNano()), Timestamp: now, Proto: "system", Kind: kind,
		Attributes: map[string]any{"error": fault, "applyBlocked": true}}, nil
}

// Embed the concrete manager to retain all its optional API capabilities. The
// boot event is emitted once and retained alongside ordinary service telemetry.
type bootEventServices struct {
	*services.Manager
	event *dpevents.Event
}

func (s *bootEventServices) ListTelemetryEvents(limit int) []dpevents.Event {
	out := s.Manager.ListTelemetryEvents(limit)
	if s.event != nil {
		out = append(out, *s.event)
	}
	if limit == 0 {
		return out
	}
	return dpevents.SelectTelemetry(out, limit)
}
