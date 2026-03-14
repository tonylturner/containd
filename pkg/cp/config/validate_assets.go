// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package config

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

func validateAssets(assets []Asset, zones []Zone) error {
	state := newAssetValidationState(zones)
	for _, a := range assets {
		if err := validateAssetIdentity(&state, a); err != nil {
			return err
		}
		if err := validateAssetZoneAndIPs(state.zoneSet, a); err != nil {
			return err
		}
		if err := validateAssetEnums(a); err != nil {
			return err
		}
	}
	return nil
}

type assetValidationState struct {
	zoneSet    map[string]struct{}
	ids        map[string]struct{}
	names      map[string]struct{}
	idsLower   map[string]struct{}
	namesLower map[string]struct{}
	aliasSeen  map[string]struct{}
}

func newAssetValidationState(zones []Zone) assetValidationState {
	zoneSet := map[string]struct{}{}
	for _, z := range zones {
		zoneSet[z.Name] = struct{}{}
	}
	return assetValidationState{
		zoneSet:    zoneSet,
		ids:        map[string]struct{}{},
		names:      map[string]struct{}{},
		idsLower:   map[string]struct{}{},
		namesLower: map[string]struct{}{},
		aliasSeen:  map[string]struct{}{},
	}
}

func validateAssetIdentity(state *assetValidationState, a Asset) error {
	if a.ID == "" {
		return errors.New("asset id cannot be empty")
	}
	if _, ok := state.ids[a.ID]; ok {
		return fmt.Errorf("duplicate asset id: %s", a.ID)
	}
	state.ids[a.ID] = struct{}{}
	state.idsLower[strings.ToLower(a.ID)] = struct{}{}
	if a.Name == "" {
		return fmt.Errorf("asset %s name cannot be empty", a.ID)
	}
	if _, ok := state.names[a.Name]; ok {
		return fmt.Errorf("duplicate asset name: %s", a.Name)
	}
	state.names[a.Name] = struct{}{}
	state.namesLower[strings.ToLower(a.Name)] = struct{}{}
	return validateAssetAlias(state, a)
}

func validateAssetAlias(state *assetValidationState, a Asset) error {
	if strings.TrimSpace(a.Alias) == "" {
		return nil
	}
	if a.Alias != strings.TrimSpace(a.Alias) {
		return fmt.Errorf("asset %s alias has leading/trailing whitespace", a.ID)
	}
	key := strings.ToLower(a.Alias)
	if _, ok := state.aliasSeen[key]; ok {
		return fmt.Errorf("duplicate asset alias: %s", a.Alias)
	}
	if _, ok := state.idsLower[key]; ok {
		return fmt.Errorf("asset alias conflicts with asset id: %s", a.Alias)
	}
	if _, ok := state.namesLower[key]; ok {
		return fmt.Errorf("asset alias conflicts with asset name: %s", a.Alias)
	}
	state.aliasSeen[key] = struct{}{}
	return nil
}

func validateAssetZoneAndIPs(zoneSet map[string]struct{}, a Asset) error {
	if a.Zone != "" {
		if _, ok := zoneSet[a.Zone]; !ok {
			return fmt.Errorf("asset %s references unknown zone %s", a.ID, a.Zone)
		}
	}
	for _, ipStr := range a.IPs {
		if net.ParseIP(ipStr) == nil {
			return fmt.Errorf("asset %s has invalid ip %q", a.ID, ipStr)
		}
	}
	return nil
}

func validateAssetEnums(a Asset) error {
	if a.Criticality != "" &&
		a.Criticality != CriticalityLow &&
		a.Criticality != CriticalityMedium &&
		a.Criticality != CriticalityHigh &&
		a.Criticality != CriticalityCritical {
		return fmt.Errorf("asset %s has invalid criticality %q", a.ID, a.Criticality)
	}
	if a.Type != "" &&
		a.Type != AssetPLC &&
		a.Type != AssetHMI &&
		a.Type != AssetSIS &&
		a.Type != AssetRTU &&
		a.Type != AssetHistorian &&
		a.Type != AssetEWS &&
		a.Type != AssetGateway &&
		a.Type != AssetLaptop &&
		a.Type != AssetOther {
		return fmt.Errorf("asset %s has invalid type %q", a.ID, a.Type)
	}
	return nil
}

func validateObjects(objects []Object) error {
	if len(objects) == 0 {
		return nil
	}
	ids := map[string]struct{}{}
	names := map[string]struct{}{}
	idsLower := map[string]struct{}{}
	namesLower := map[string]struct{}{}
	for _, obj := range objects {
		if err := validateObjectIdentity(ids, names, idsLower, namesLower, obj); err != nil {
			return err
		}
		if err := validateObjectType(obj); err != nil {
			return err
		}
	}
	for _, obj := range objects {
		if err := validateObjectGroupMembers(ids, obj); err != nil {
			return err
		}
	}
	if len(idsLower) != len(ids) || len(namesLower) != len(names) {
		return errors.New("object ids and names must be unique case-insensitively")
	}
	return nil
}

func validateObjectIdentity(ids, names, idsLower, namesLower map[string]struct{}, obj Object) error {
	if obj.ID == "" {
		return errors.New("object id cannot be empty")
	}
	if _, ok := ids[obj.ID]; ok {
		return fmt.Errorf("duplicate object id: %s", obj.ID)
	}
	ids[obj.ID] = struct{}{}
	idsLower[strings.ToLower(obj.ID)] = struct{}{}
	if obj.Name == "" {
		return fmt.Errorf("object %s name cannot be empty", obj.ID)
	}
	if _, ok := names[obj.Name]; ok {
		return fmt.Errorf("duplicate object name: %s", obj.Name)
	}
	names[obj.Name] = struct{}{}
	namesLower[strings.ToLower(obj.Name)] = struct{}{}
	return nil
}

func validateObjectType(obj Object) error {
	switch obj.Type {
	case ObjectHost:
		return validateObjectHostAddresses(obj)
	case ObjectSubnet:
		return validateObjectSubnetAddresses(obj)
	case ObjectGroup:
		return nil
	case ObjectService:
		return validateObjectService(obj)
	default:
		return fmt.Errorf("object %s has invalid type %q", obj.ID, obj.Type)
	}
}

func validateObjectHostAddresses(obj Object) error {
	for _, addr := range obj.Addresses {
		if err := validateObjectHostAddress(addr); err != nil {
			return fmt.Errorf("object %s has invalid host address %q: %w", obj.ID, addr, err)
		}
	}
	return nil
}

func validateObjectSubnetAddresses(obj Object) error {
	for _, addr := range obj.Addresses {
		if err := validateObjectSubnetAddress(addr); err != nil {
			return fmt.Errorf("object %s has invalid subnet %q: %w", obj.ID, addr, err)
		}
	}
	return nil
}

func validateObjectService(obj Object) error {
	if len(obj.Protocols) == 0 {
		return fmt.Errorf("object %s service must include at least one protocol", obj.ID)
	}
	for _, p := range obj.Protocols {
		if strings.TrimSpace(p.Name) == "" {
			return fmt.Errorf("object %s service protocol name cannot be empty", obj.ID)
		}
		if err := validatePortString(p.Port); err != nil {
			return fmt.Errorf("object %s service protocol port %q invalid: %w", obj.ID, p.Port, err)
		}
	}
	return nil
}

func validateObjectGroupMembers(ids map[string]struct{}, obj Object) error {
	if obj.Type != ObjectGroup {
		return nil
	}
	for _, member := range obj.Members {
		if member == "" {
			return fmt.Errorf("object %s group member cannot be empty", obj.ID)
		}
		if member == obj.ID {
			return fmt.Errorf("object %s group cannot include itself", obj.ID)
		}
		if _, ok := ids[member]; !ok {
			return fmt.Errorf("object %s references unknown member %s", obj.ID, member)
		}
	}
	return nil
}

func validateObjectHostAddress(addr string) error {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return errors.New("address cannot be empty")
	}
	if strings.Contains(addr, "/") {
		return errors.New("host addresses must not be CIDR")
	}
	if net.ParseIP(addr) != nil {
		return nil
	}
	if strings.ContainsAny(addr, " \t\n") {
		return errors.New("hostname contains whitespace")
	}
	if err := validateHostname(addr); err != nil {
		return err
	}
	return nil
}

func validateObjectSubnetAddress(addr string) error {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return errors.New("subnet cannot be empty")
	}
	if _, _, err := net.ParseCIDR(addr); err != nil {
		return err
	}
	return nil
}

func validatePortString(port string) error {
	port = strings.TrimSpace(port)
	if port == "" {
		return nil
	}
	parts := strings.Split(port, "-")
	if len(parts) > 2 {
		return errors.New("invalid port range")
	}
	start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || start < 1 || start > 65535 {
		return fmt.Errorf("invalid port %q", port)
	}
	if len(parts) == 1 {
		return nil
	}
	end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil || end < 1 || end > 65535 || end < start {
		return fmt.Errorf("invalid port range %q", port)
	}
	return nil
}
