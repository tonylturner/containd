// SPDX-License-Identifier: Apache-2.0
package mgmtapp

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	httpapi "github.com/tonylturner/containd/api/http"
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
	httpAddr := config.ProcessEnv(config.EnvManagementHTTPAddr)
	if httpAddr != "" {
		if err := r.ValidateListen(httpAddr); err != nil {
			return fmt.Errorf("%s: %w", config.EnvManagementHTTPAddr, err)
		}
	} else {
		httpAddr = fmt.Sprintf(":%d", r.Port)
	}
	for _, key := range []string{config.EnvManagementHTTPSAddr, config.EnvSSHAddr} {
		addr := config.ProcessEnv(key)
		conflict := config.ManagementListenerOverlaps(addr, r)
		if key == config.EnvManagementHTTPSAddr {
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
	if config.ManagementListenerConflictsHTTP(config.ProcessEnv(config.EnvSSHAddr), config.EffectiveManagementListeners(cfg).HTTP.Addr, false, r) {
		return fmt.Errorf("%s conflicts with reserved management path HTTP socket", config.EnvSSHAddr)
	}
	return nil
}

// bootConflict is why the stored running configuration must not be replayed
// at this boot. Without a reservation that is only its own validation, which
// an upgrade can tighten under an existing store.
func bootConflict(cfg *config.Config, r *mgmtpath.Reservation) error {
	_, _, err := config.Effective(cfg, r)
	if r != nil {
		err = errors.Join(err, validateReservedStartup(cfg, r))
	}
	return err
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
	return httpapi.WithApplianceListeners(cfg, r)
}

// recordBootDecision persists every boot's recovery decision. A refused
// stored configuration never stops management: replay is gated and the engine
// gets the fail-closed recovery ruleset until a valid commit, rollback or
// factory reset (see api/http ApplyBootConfig).
func recordBootDecision(logger *zap.SugaredLogger, stores mgmtStores, cfg *config.Config, r *mgmtpath.Reservation) (*dpevents.Event, []dpevents.Event, error) {
	event, err := persistBootFault(logger, stores, bootConflict(cfg, r), r)
	if err != nil {
		return nil, nil, err
	}
	_, faults, _ := config.Effective(cfg, r)
	if recorder, ok := stores.store.(interface {
		SetServiceBootFaults(context.Context, []config.ServiceFault) error
	}); ok {
		if err := recorder.SetServiceBootFaults(context.Background(), services.ConfigFaults(faults)); err != nil {
			logger.Errorw("record service boot faults", "error", err)
		}
	}
	byService := map[string][]string{}
	var order []string
	for _, fault := range faults {
		if _, exists := byService[fault.Service]; !exists {
			order = append(order, fault.Service)
		}
		// Quote controls (including CR/LF/NUL) so operator input cannot forge
		// log lines. Validators never echo auth material.
		message := strconv.QuoteToASCII(fault.Err.Error())
		byService[fault.Service] = append(byService[fault.Service], message[1:len(message)-1])
	}
	var events []dpevents.Event
	for _, service := range order {
		detail := strings.Join(byService[service], "; ")
		now := time.Now().UTC()
		const kind = "service.config_fault"
		if err := stores.auditStore.Add(context.Background(), audit.Record{
			Timestamp: now, Actor: "system", Source: "management", Action: kind,
			Target: service, Result: "fault", Detail: detail,
		}); err != nil {
			logger.Errorw("record service boot fault", "error", err)
		}
		logger.Errorw(kind, "service", service, "error", detail)
		events = append(events, dpevents.Event{
			ID: uint64(now.UnixNano()), Timestamp: now, Proto: "system", Kind: kind,
			Attributes: map[string]any{"service": service, "error": detail},
		})
	}
	return event, events, nil
}

// persistBootFault records conflict, or its absence, as this boot's
// recovery decision, with an audit record and the returned event when
// there is one.
func persistBootFault(logger *zap.SugaredLogger, stores mgmtStores, conflict error, r *mgmtpath.Reservation) (*dpevents.Event, error) {
	store, ok := stores.store.(interface {
		SetManagementBootFault(context.Context, string) error
	})
	if !ok {
		return nil, errors.New("config store does not support management boot fault persistence")
	}
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
	kind := "management.recovery.boot_fault"
	if r != nil {
		kind = "management.reservation.boot_fault"
	}
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
	event  *dpevents.Event
	events []dpevents.Event
}

func (s *bootEventServices) ListTelemetryEvents(limit int) []dpevents.Event {
	out := s.Manager.ListTelemetryEvents(limit)
	if s.event != nil {
		out = append(out, *s.event)
	}
	out = append(out, s.events...)
	if limit == 0 {
		return out
	}
	return dpevents.SelectTelemetry(out, limit)
}
