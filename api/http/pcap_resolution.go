// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"context"
	"fmt"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func resolvePCAPConfig(ctx context.Context, engine EngineClient, running config.Config, capture config.PCAPConfig) (config.PCAPConfig, error) {
	if len(capture.Interfaces) == 0 && len(capture.Zones) == 0 {
		return config.PCAPConfig{}, fmt.Errorf("pcap requires at least one interface or zone")
	}
	state, err := engine.ListInterfaceState(ctx)
	if err != nil {
		return config.PCAPConfig{}, fmt.Errorf("read kernel interfaces: %w", err)
	}
	available := make(map[string]struct{}, len(state))
	for _, iface := range state {
		available[iface.Name] = struct{}{}
	}

	logical := make(map[string]config.Interface, len(running.Interfaces))
	for _, iface := range running.Interfaces {
		logical[iface.Name] = iface
	}
	zones := make(map[string]struct{}, len(running.Zones))
	for _, zone := range running.Zones {
		zones[zone.Name] = struct{}{}
	}

	resolved := make([]string, 0, len(capture.Interfaces)+len(running.Interfaces))
	seen := make(map[string]struct{})
	addDevice := func(device, ref string, requireExisting bool) error {
		if device == "" {
			return fmt.Errorf("pcap interface %q resolves to an empty kernel device", ref)
		}
		if _, ok := available[device]; requireExisting && !ok {
			return fmt.Errorf("pcap interface %q resolves to missing kernel device %q", ref, device)
		}
		if _, ok := seen[device]; !ok {
			seen[device] = struct{}{}
			resolved = append(resolved, device)
		}
		return nil
	}
	resolveRef := func(ref string) error {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			return fmt.Errorf("pcap.interfaces cannot include empty name")
		}
		if iface, ok := logical[ref]; ok {
			device := strings.TrimSpace(iface.Device)
			if device == "" {
				device = strings.TrimSpace(iface.Name)
			}
			return addDevice(device, ref, false)
		}
		if _, ok := available[ref]; ok {
			return addDevice(ref, ref, true)
		}
		return fmt.Errorf("pcap interface %q is not a configured logical interface or existing kernel device", ref)
	}

	for _, ref := range capture.Interfaces {
		if err := resolveRef(ref); err != nil {
			return config.PCAPConfig{}, err
		}
	}
	for _, name := range capture.Zones {
		name = strings.TrimSpace(name)
		if name == "" {
			return config.PCAPConfig{}, fmt.Errorf("pcap.zones cannot include empty name")
		}
		if _, ok := zones[name]; !ok {
			return config.PCAPConfig{}, fmt.Errorf("unknown pcap zone %q", name)
		}
		found := false
		for _, iface := range running.Interfaces {
			if iface.Zone != name {
				continue
			}
			found = true
			device := strings.TrimSpace(iface.Device)
			if device == "" {
				device = strings.TrimSpace(iface.Name)
			}
			if err := addDevice(device, name, false); err != nil {
				return config.PCAPConfig{}, fmt.Errorf("pcap zone %q: %w", name, err)
			}
		}
		if !found {
			return config.PCAPConfig{}, fmt.Errorf("pcap zone %q has no configured interfaces", name)
		}
	}
	if len(resolved) == 0 {
		return config.PCAPConfig{}, fmt.Errorf("pcap interface and zone selection resolves to no devices")
	}
	capture.Interfaces = resolved
	capture.Zones = nil
	return capture, nil
}
