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
	// Config.Validate is fail-fast. Scan selection follows service validation,
	// and must not be masked by an earlier service-only fault.
	conflict := cfg.Validate()
	if faults, other := splitServiceFaults(conflict); len(faults) > 0 && other == nil {
		_, scanErr := config.ValidateScanSelection(cfg)
		conflict = errors.Join(conflict, scanErr)
	}
	if r != nil {
		conflict = errors.Join(conflict, config.ValidateManagementReservation(cfg, r), validateReservedStartup(cfg, r))
	}
	if _, other := splitServiceFaults(conflict); other == nil {
		return nil
	}
	return conflict
}

// Inspect every branch of a joined error, not merely the first errors.As match:
// a mixed error must never be mistaken for a service-only failure.
func splitServiceFaults(err error) ([]*config.ServiceConfigError, error) {
	if err == nil {
		return nil, nil
	}
	if fault, ok := err.(*config.ServiceConfigError); ok {
		return []*config.ServiceConfigError{fault}, nil
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var faults []*config.ServiceConfigError
		var other []error
		for _, child := range joined.Unwrap() {
			f, e := splitServiceFaults(child)
			faults = append(faults, f...)
			other = append(other, e)
		}
		return faults, errors.Join(other...)
	}
	if child := errors.Unwrap(err); child != nil {
		faults, other := splitServiceFaults(child)
		if other == nil {
			return faults, nil
		}
		return faults, err
	}
	return nil, err
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
func recordBootDecision(logger *zap.SugaredLogger, stores mgmtStores, cfg *config.Config, r *mgmtpath.Reservation) (*dpevents.Event, error) {
	event, err := persistBootFault(logger, stores, bootConflict(cfg, r), r)
	if err != nil {
		return nil, err
	}
	faults, _ := splitServiceFaults(config.ValidateServiceConfigs(cfg))
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
			return nil, fmt.Errorf("record service boot fault: %w", err)
		}
		logger.Errorw(kind, "service", service, "error", detail)
		events = append(events, dpevents.Event{
			ID: uint64(now.UnixNano()), Timestamp: now, Proto: "system", Kind: kind,
			Attributes: map[string]any{"service": service, "error": detail},
		})
	}
	if len(events) == 0 {
		return event, nil
	}
	if event != nil {
		events = append(events, *event)
	}
	// The assembly stores one boot event. Retain its primary event and carry the
	// complete batch to the telemetry boundary, which exposes individual events.
	primary := events[0]
	if event != nil {
		primary = *event
	}
	attrs := make(map[string]any, len(primary.Attributes)+1)
	for key, value := range primary.Attributes {
		attrs[key] = value
	}
	attrs["bootEvents"] = events
	primary.Attributes = attrs
	return &primary, nil
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
	event *dpevents.Event
}

func (s *bootEventServices) ListTelemetryEvents(limit int) []dpevents.Event {
	out := s.Manager.ListTelemetryEvents(limit)
	if s.event != nil {
		out = append(out, bootEvents(s.event)...)
	}
	if limit == 0 {
		return out
	}
	return dpevents.SelectTelemetry(out, limit)
}

func bootEvents(event *dpevents.Event) []dpevents.Event {
	if events, ok := event.Attributes["bootEvents"].([]dpevents.Event); ok {
		return events
	}
	return []dpevents.Event{*event}
}
