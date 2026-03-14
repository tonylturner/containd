// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cli

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// setFirewallICSRuleAPI creates or updates an ICS-specific firewall rule.
//
// Usage:
//
//	set firewall ics-rule <id> <action> <protocol> [options...]
//
// Options:
//
//	--src-zone <zone>
//	--dst-zone <zone>
//	--function-code <codes>   (comma-separated uint8 values)
//	--unit-id <id>
//	--addresses <ranges>      (comma-separated, e.g. "0x0100-0x01FF,0x0200")
//	--read-only
//	--write-only
//	--mode <learn|enforce>
func setFirewallICSRuleAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		rule, err := parseFirewallICSRuleArgs(args)
		if err != nil {
			return err
		}
		return api.postJSON(ctx, "/api/v1/firewall/ics-rules", rule, out)
	}
}

func parseFirewallICSRuleArgs(args []string) (config.Rule, error) {
	if len(args) < 3 {
		return config.Rule{}, fmt.Errorf("usage: set firewall ics-rule <id> <action> <protocol> [--src-zone <zone>] [--dst-zone <zone>] [--function-code <codes>] [--unit-id <id>] [--addresses <ranges>] [--read-only] [--write-only] [--mode <learn|enforce>]")
	}

	rule := config.Rule{
		ID:     args[0],
		Action: config.Action(strings.ToUpper(args[1])),
		ICS: config.ICSPredicate{
			Protocol: args[2],
		},
	}

	for i := 3; i < len(args); i++ {
		next, err := applyFirewallICSRuleArg(&rule, args, i)
		if err != nil {
			return config.Rule{}, err
		}
		i = next
	}
	return rule, nil
}

func applyFirewallICSRuleArg(rule *config.Rule, args []string, index int) (int, error) {
	switch args[index] {
	case "--src-zone":
		value, next, err := firewallICSRuleValue(args, index, "--src-zone")
		if err != nil {
			return index, err
		}
		rule.SourceZones = []string{value}
		return next, nil
	case "--dst-zone":
		value, next, err := firewallICSRuleValue(args, index, "--dst-zone")
		if err != nil {
			return index, err
		}
		rule.DestZones = []string{value}
		return next, nil
	case "--function-code":
		value, next, err := firewallICSRuleValue(args, index, "--function-code")
		if err != nil {
			return index, err
		}
		codes, err := parseUint8CSV(value)
		if err != nil {
			return index, fmt.Errorf("invalid --function-code: %w", err)
		}
		rule.ICS.FunctionCode = codes
		return next, nil
	case "--unit-id":
		value, next, err := firewallICSRuleValue(args, index, "--unit-id")
		if err != nil {
			return index, err
		}
		uid, err := parseFirewallICSUnitID(value)
		if err != nil {
			return index, err
		}
		rule.ICS.UnitID = uid
		return next, nil
	case "--addresses":
		value, next, err := firewallICSRuleValue(args, index, "--addresses")
		if err != nil {
			return index, err
		}
		rule.ICS.Addresses = strings.Split(value, ",")
		return next, nil
	case "--read-only":
		rule.ICS.ReadOnly = true
		return index, nil
	case "--write-only":
		rule.ICS.WriteOnly = true
		return index, nil
	case "--mode":
		value, next, err := firewallICSRuleValue(args, index, "--mode")
		if err != nil {
			return index, err
		}
		if err := validateFirewallICSMode(value); err != nil {
			return index, err
		}
		rule.ICS.Mode = value
		return next, nil
	default:
		return index, fmt.Errorf("unknown option: %s", args[index])
	}
}

func firewallICSRuleValue(args []string, index int, flag string) (string, int, error) {
	index++
	if index >= len(args) {
		return "", index, fmt.Errorf("%s requires a value", flag)
	}
	return args[index], index, nil
}

func parseFirewallICSUnitID(value string) (*uint8, error) {
	v, err := strconv.ParseUint(value, 10, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid --unit-id: %w", err)
	}
	uid := uint8(v)
	return &uid, nil
}

func validateFirewallICSMode(mode string) error {
	if mode != "learn" && mode != "enforce" {
		return fmt.Errorf("--mode must be 'learn' or 'enforce'")
	}
	return nil
}

// showFirewallICSRulesAPI lists firewall rules that have ICS predicates.
func showFirewallICSRulesAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var rules []config.Rule
		if err := api.getJSON(ctx, "/api/v1/firewall/ics-rules", &rules); err != nil {
			return err
		}
		t := newTable("ID", "ACTION", "SRC_ZONES", "DST_ZONES", "PROTOCOL", "FUNC_CODES", "UNIT_ID", "ADDRESSES", "R/W", "MODE")
		for _, r := range rules {
			fcs := make([]string, 0, len(r.ICS.FunctionCode))
			for _, fc := range r.ICS.FunctionCode {
				fcs = append(fcs, strconv.Itoa(int(fc)))
			}
			unitID := "—"
			if r.ICS.UnitID != nil {
				unitID = strconv.Itoa(int(*r.ICS.UnitID))
			}
			rw := "—"
			if r.ICS.ReadOnly {
				rw = "read-only"
			} else if r.ICS.WriteOnly {
				rw = "write-only"
			}
			mode := "—"
			if r.ICS.Mode != "" {
				mode = r.ICS.Mode
			}
			t.addRow(
				r.ID,
				string(r.Action),
				joinCSV(r.SourceZones),
				joinCSV(r.DestZones),
				r.ICS.Protocol,
				joinCSV(fcs),
				unitID,
				joinCSV(r.ICS.Addresses),
				rw,
				mode,
			)
		}
		t.render(out)
		return nil
	}
}

// parseUint8CSV parses a comma-separated list of uint8 values.
func parseUint8CSV(s string) ([]uint8, error) {
	parts := strings.Split(s, ",")
	result := make([]uint8, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		v, err := strconv.ParseUint(p, 10, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid function code %q: %w", p, err)
		}
		result = append(result, uint8(v))
	}
	return result, nil
}
