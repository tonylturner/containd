// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// discoverLocalIPv4 reads all addresses, including secondaries. Configured
// devices absent from the namespace have an authoritative empty set.
func discoverLocalIPv4(snap *rules.Snapshot) (map[string][]netip.Addr, error) {
	out := map[string][]netip.Addr{}
	for _, devices := range snap.ZoneIfaces {
		for _, device := range devices {
			out[device] = nil
		}
	}
	for _, f := range snap.ForwardMatches {
		for _, device := range f.IngressDevices {
			out[device] = nil
		}
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range interfaces {
		if _, wanted := out[iface.Name]; !wanted {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, address := range addrs {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil {
				return nil, err
			}
			if prefix.Addr().Is4() {
				out[iface.Name] = append(out[iface.Name], prefix.Addr())
			}
		}
		slices.SortFunc(out[iface.Name], netip.Addr.Compare)
		out[iface.Name] = slices.Compact(out[iface.Name])
	}
	return out, nil
}

// RefreshLocalAddresses updates only nft set elements and their immutable
// userspace resolver publication. It never reloads hooks, flips P or sweeps CT.
func (e *Engine) RefreshLocalAddresses(ctx context.Context) error {
	e.lifecycleMu.Lock()
	defer e.lifecycleMu.Unlock()
	return e.refreshLocalAddresses(ctx)
}

func (e *Engine) refreshLocalAddresses(ctx context.Context) error {
	old := e.ruleSnap.Load()
	if old == nil || !e.admission.installed || e.compiler == nil {
		return nil
	}
	addrs, err := e.localIPv4(old)
	if err != nil {
		return e.policyFault(faultAddresses, err)
	}
	if maps.EqualFunc(old.LocalIPv4ByDevice, addrs, slices.Equal[[]netip.Addr]) {
		e.iec.health.clear(faultAddresses)
		return nil
	}
	next := *old
	next.LocalIPv4ByDevice = addrs
	signature, err := e.policySignature(next)
	if err != nil {
		return err
	}
	var script strings.Builder
	var devices []string
	for device := range addrs {
		devices = append(devices, device)
	}
	slices.Sort(devices)
	for _, device := range devices {
		if slices.Equal(old.LocalIPv4ByDevice[device], addrs[device]) {
			continue
		}
		update, err := e.compiler.LocalAddressUpdate(device, addrs[device])
		if err != nil {
			return e.policyFault(faultAddresses, err)
		}
		script.WriteString(update)
	}
	e.policyMu.Lock()
	defer e.policyMu.Unlock()
	if script.Len() != 0 {
		if err := e.applier.Apply(ctx, script.String()); err != nil {
			return e.policyFault(faultAddresses, err)
		}
	}
	e.ruleSnap.Update(&next)
	e.iec.mu.Lock()
	e.iec.snap, e.iec.policy = &next, e.iec.newPolicy(&next)
	e.iec.mu.Unlock()
	e.gate.mu.Lock()
	e.gate.snap = &next
	e.gate.mu.Unlock()
	e.admission.signature = signature
	e.verdictCache.Flush()
	e.iec.health.clear(faultAddresses)
	return nil
}

// Polling complements route notifications and recovers lost notifications.
// TryLock avoids joining lifecycleMu while Reconfigure waits for this run.
func (e *Engine) runAddressUpdates(ctx context.Context, onError func(error)) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-e.zones.changes:
		}
		if !e.lifecycleMu.TryLock() {
			continue
		}
		err := e.refreshLocalAddresses(ctx)
		e.lifecycleMu.Unlock()
		if err != nil && onError != nil && ctx.Err() == nil {
			onError(err)
		}
	}
}
