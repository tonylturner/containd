// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/tonylturner/containd/pkg/app/convergence"
	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/common/trust"
	"github.com/tonylturner/containd/pkg/cp/compile"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/services"
	"github.com/tonylturner/containd/pkg/dp/enforce"
	"github.com/tonylturner/containd/pkg/dp/netcfg"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// RuntimeEnvironment adapts immutable boot authority and existing material
// owners to convergence. It never persists an effective runtime projection.
type RuntimeEnvironment struct {
	Store           config.Store
	Engine          EngineClient
	RefreshMaterial func(context.Context, *config.RunningSnapshot) error
}

func (e *RuntimeEnvironment) Prepare(_ context.Context, next *config.RunningSnapshot) (convergence.Prepared, error) {
	if next == nil || next.Config == nil {
		return convergence.Prepared{}, errors.New("missing running snapshot")
	}
	effective, faults, err := config.EffectiveForStore(e.Store, next.Config)
	if err != nil {
		return convergence.Prepared{}, err
	}
	if config.ReservationForStore(e.Store) == nil {
		bindUnboundDefaultInterfaceDevices(effective)
	}
	bundle, err := trust.LoadBundle(trustedCABundlePath(next.Config))
	if err != nil {
		return convergence.Prepared{}, err
	}
	// Requirements come from original desired policy, before quarantine. The
	// validated projection preserves firewall predicates and AV gate selection.
	snapshot, err := compile.CompileSnapshot(effective)
	if err != nil {
		return convergence.Prepared{}, err
	}
	selection := desiredSelection(next.Config, snapshot)
	return convergence.Prepared{Effective: effective, Faults: faults, Trust: bundle, Selection: selection}, nil
}

func desiredSelection(desired *config.Config, snapshot rules.Snapshot) protection.Selection {
	s := protection.Selection{Forwarding: netcfg.RequiresIPv4Forwarding(desired.Interfaces),
		Scan: desired.Services.AV.ScanGateEnabled()}
	av := desired.Services.AV
	mode := strings.ToLower(strings.TrimSpace(av.Mode))
	s.Trust = av.Enabled && ((mode == "" || mode == "clamav") && av.ClamAV.FreshclamEnabled || mode == "icap" && hasTLSICAP(av))
	group := desired.DataPlane.NFQueueGroup
	c := enforce.NewCompilerWithSettings(enforce.CompilerSettings{NFQueueGroup: group}, nil)
	for _, entry := range snapshot.Firewall {
		if !entry.Action.Decides() || entry.ICS.Protocol == "" || group == 0 {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(entry.ICS.Protocol), "iec104") {
			s.NFQueues = []uint16{group}
			continue
		}
		scope := entry
		scope.ICS.Mode = "enforce"
		if c.SteersIEC104(&rules.Snapshot{DPIMode: "enforce", Firewall: []rules.Entry{scope}}) {
			s.NFQueues = []uint16{group}
			s.IECEnvelope = s.IECEnvelope || !rules.MonitorICS(entry, snapshot.DPIMode)
		}
	}
	return s
}

func hasTLSICAP(av config.AVConfig) bool {
	for _, server := range av.ICAP.Servers {
		if server.UseTLS {
			return true
		}
	}
	return false
}

func (e *RuntimeEnvironment) Recovery(ctx context.Context, state config.RunningState) (convergence.RecoveryPlan, bool, error) {
	err := config.CheckManagementBootFault(ctx, e.Store)
	if err != nil && !errors.Is(err, config.ErrManagementBootFault) {
		return convergence.RecoveryPlan{}, false, err
	}
	blocked := state.Transition != nil && state.Transition.State != config.TransitionReapplyPending
	recovery := err != nil || blocked
	// Always supply a validated plan: compensation can request immediate recovery
	// even if the boot gate was just cleared by the attempted transition.
	var stored *config.Config
	if state.Running != nil {
		stored = state.Running.Config
	}
	r := config.ReservationForStore(e.Store)
	if !recovery && stored == nil {
		return convergence.RecoveryPlan{}, false, nil
	}
	if r == nil && stored == nil {
		return convergence.RecoveryPlan{}, recovery, errors.New("recovery management access unavailable")
	}
	if err := config.ValidateManagementDataPlane(config.DataPlaneConfig{Enforcement: true}, r); err != nil {
		return convergence.RecoveryPlan{}, recovery, err
	}
	snap := RecoverySnapshot(stored, r)
	var addresses []config.Interface
	if r == nil {
		addresses = recoveryAddresses(stored, snap.LocalInput)
	}
	return convergence.RecoveryPlan{Rules: snap, Addresses: addresses}, recovery, nil
}

func (e *RuntimeEnvironment) Refresh(ctx context.Context, snapshot *config.RunningSnapshot) error {
	if e.RefreshMaterial == nil {
		return errors.New("referenced-material owner unavailable")
	}
	return e.RefreshMaterial(ctx, snapshot)
}

// RefreshLocalMaterial reloads referenced bytes through the actual owners. It
// is explicit SIGHUP work, never a periodic retry or a new service supervisor.
func RefreshLocalMaterial(ctx context.Context, store config.Store, manager *services.Manager, snapshot *config.RunningSnapshot) error {
	cfg, _, err := config.EffectiveForStore(store, snapshot.Config)
	if err != nil {
		return err
	}
	var failures []error
	apply := func(deliver, quarantine func() error) {
		if err := deliver(); err != nil {
			// Invalidate inherited owner proof through actual safe teardown.
			// An invalid edited file must not leave the old live process
			// eligible for equality-only adoption on the next attempt.
			failures = append(failures, errors.Join(err, quarantine()))
		}
	}
	if manager.Proxy != nil {
		apply(func() error { return manager.Proxy.Apply(ctx, cfg.Services.Proxy) },
			func() error { return manager.Proxy.Apply(ctx, config.ProxyConfig{}) })
	}
	if manager.VPN != nil {
		apply(func() error { return manager.VPN.Apply(ctx, cfg.Services.VPN) },
			func() error { return manager.VPN.Apply(ctx, config.VPNConfig{}) })
	}
	if manager.DNS != nil {
		apply(func() error { return manager.DNS.Apply(ctx, cfg.Services.DNS) },
			func() error { return manager.DNS.Apply(ctx, config.DNSConfig{}) })
	}
	if manager.NTP != nil {
		apply(func() error { return manager.NTP.Apply(ctx, cfg.Services.NTP) },
			func() error { return manager.NTP.Apply(ctx, config.NTPConfig{}) })
	}
	if manager.Syslog != nil {
		apply(func() error { return manager.Syslog.Apply(ctx, cfg.Services.Syslog) },
			func() error { return manager.Syslog.Apply(ctx, config.SyslogConfig{}) })
	}
	if manager.DHCP != nil {
		apply(func() error { return manager.DHCP.Apply(ctx, cfg.Services.DHCP) },
			func() error { return manager.DHCP.Apply(ctx, config.DHCPConfig{}) })
	}
	return errors.Join(failures...)
}

func (e *RuntimeEnvironment) SavedPCAP(ctx context.Context, previous, next *config.RunningSnapshot) []string {
	if previous != nil && reflect.DeepEqual(previous.PCAP, next.PCAP) {
		return nil
	}
	var warnings []string
	if _, err := e.Engine.SetPcapConfig(ctx, next.PCAP); err != nil {
		warnings = append(warnings, fmt.Sprintf("pcap config: %v", err))
	}
	if next.PCAP.Enabled {
		if _, err := e.Engine.StartPcap(ctx, next.PCAP); err != nil && !strings.Contains(err.Error(), "already running") {
			warnings = append(warnings, fmt.Sprintf("pcap start: %v", err))
		}
	} else if _, err := e.Engine.StopPcap(ctx); err != nil {
		warnings = append(warnings, fmt.Sprintf("pcap stop: %v", err))
	}
	return warnings
}
