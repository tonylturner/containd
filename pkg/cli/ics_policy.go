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
		if len(args) < 3 {
			return fmt.Errorf("usage: set firewall ics-rule <id> <action> <protocol> [--src-zone <zone>] [--dst-zone <zone>] [--function-code <codes>] [--unit-id <id>] [--addresses <ranges>] [--read-only] [--write-only] [--mode <learn|enforce>]")
		}

		rule := config.Rule{
			ID:     args[0],
			Action: config.Action(strings.ToUpper(args[1])),
			ICS: config.ICSPredicate{
				Protocol: args[2],
			},
		}

		// Parse optional flags.
		i := 3
		for i < len(args) {
			switch args[i] {
			case "--src-zone":
				i++
				if i >= len(args) {
					return fmt.Errorf("--src-zone requires a value")
				}
				rule.SourceZones = []string{args[i]}
			case "--dst-zone":
				i++
				if i >= len(args) {
					return fmt.Errorf("--dst-zone requires a value")
				}
				rule.DestZones = []string{args[i]}
			case "--function-code":
				i++
				if i >= len(args) {
					return fmt.Errorf("--function-code requires a value")
				}
				codes, err := parseUint8CSV(args[i])
				if err != nil {
					return fmt.Errorf("invalid --function-code: %w", err)
				}
				rule.ICS.FunctionCode = codes
			case "--unit-id":
				i++
				if i >= len(args) {
					return fmt.Errorf("--unit-id requires a value")
				}
				v, err := strconv.ParseUint(args[i], 10, 8)
				if err != nil {
					return fmt.Errorf("invalid --unit-id: %w", err)
				}
				uid := uint8(v)
				rule.ICS.UnitID = &uid
			case "--addresses":
				i++
				if i >= len(args) {
					return fmt.Errorf("--addresses requires a value")
				}
				rule.ICS.Addresses = strings.Split(args[i], ",")
			case "--read-only":
				rule.ICS.ReadOnly = true
			case "--write-only":
				rule.ICS.WriteOnly = true
			case "--mode":
				i++
				if i >= len(args) {
					return fmt.Errorf("--mode requires a value")
				}
				mode := args[i]
				if mode != "learn" && mode != "enforce" {
					return fmt.Errorf("--mode must be 'learn' or 'enforce'")
				}
				rule.ICS.Mode = mode
			default:
				return fmt.Errorf("unknown option: %s", args[i])
			}
			i++
		}

		return api.postJSON(ctx, "/api/v1/firewall/ics-rules", rule, out)
	}
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
