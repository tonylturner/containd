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
	dprules "github.com/tonylturner/containd/pkg/dp/rules"
)

// setFirewallICSRuleAPI creates an ICS-specific firewall rule.
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
//	--object-classes <classes> (CIP, comma-separated decimal or 0x-prefixed uint16 values)
//	--unit-id <id>
//	--addresses <ranges>      (comma-separated, e.g. "0x0100-0x01FF,0x0200")
//	--read-only
//	--write-only
//	--type-ids <ids>          (IEC104, comma-separated, e.g. "45,46")
//	--classes <classes>       (IEC104, monitor|control|system|unknown)
//	--ca <addresses>          (IEC104, comma-separated, 0..65534)
//	--ioa <ranges>            (IEC104, comma-separated decimal addresses/ranges)
//	--direction <request|response>
//	--mode <learn|enforce>
//	--masters / --outstations <stations> (DNP3, 0..65519)
//	--groups / --variations <values>     (DNP3, 0..255)
//	--instances / --attributes <values> (CIP, 0..65535)
//	--tags <paths>                      (CIP, comma-separated tag paths)
//	--cot <values> / --originators <values> (IEC104, 1..63 / 0..255)
//	--negative <true|false> / --test <true|false> (IEC104)
//	--select-execute <select|execute>    (IEC104)
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
		return config.Rule{}, fmt.Errorf("usage: set firewall ics-rule <id> <action> <protocol> [--src-zone <zone>] [--dst-zone <zone>] [--function-code <codes>] [--object-classes <classes>] [--unit-id <id>] [--addresses <ranges>] [--read-only] [--write-only] [--type-ids <ids>] [--classes <classes>] [--ca <addresses>] [--ioa <ranges>] [--direction <request|response>] [--mode <learn|enforce>] [--masters <stations>] [--outstations <stations>] [--groups <groups>] [--variations <variations>] [--instances <instances>] [--attributes <attributes>] [--tags <paths>] [--cot <causes>] [--originators <addresses>] [--negative <true|false>] [--test <true|false>] [--select-execute <select|execute>]")
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
	case "--masters", "--outstations", "--groups", "--variations", "--instances", "--attributes", "--tags", "--cot", "--originators", "--negative", "--test", "--select-execute":
		value, next, err := firewallICSRuleValue(args, index, args[index])
		if err != nil {
			return index, err
		}
		return next, applyICSSelector(&rule.ICS, args[index], value)
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
	case "--object-classes":
		value, next, err := firewallICSRuleValue(args, index, "--object-classes")
		if err != nil {
			return index, err
		}
		classes, err := parseCIPObjectClasses(value)
		if err != nil {
			return index, err
		}
		rule.ICS.ObjectClasses = classes
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
	case "--type-ids":
		value, next, err := firewallICSRuleValue(args, index, "--type-ids")
		if err != nil {
			return index, err
		}
		typeIDs, err := parseIEC104TypeIDs(value)
		if err != nil {
			return index, err
		}
		rule.ICS.TypeIDs = typeIDs
		return next, nil
	case "--classes":
		value, next, err := firewallICSRuleValue(args, index, "--classes")
		if err != nil {
			return index, err
		}
		classes, err := parseIEC104Classes(value)
		if err != nil {
			return index, err
		}
		rule.ICS.Classes = classes
		return next, nil
	case "--ca":
		value, next, err := firewallICSRuleValue(args, index, "--ca")
		if err != nil {
			return index, err
		}
		cas, err := parseIEC104CAs(value)
		if err != nil {
			return index, err
		}
		rule.ICS.CA = cas
		return next, nil
	case "--ioa":
		value, next, err := firewallICSRuleValue(args, index, "--ioa")
		if err != nil {
			return index, err
		}
		ioa, err := parseIEC104IOARanges(value)
		if err != nil {
			return index, err
		}
		rule.ICS.IOA = ioa
		return next, nil
	case "--direction":
		value, next, err := firewallICSRuleValue(args, index, "--direction")
		if err != nil {
			return index, err
		}
		if value != "request" && value != "response" {
			return index, fmt.Errorf("--direction must be 'request' or 'response'")
		}
		rule.ICS.Direction = value
		return next, nil
	default:
		return index, fmt.Errorf("unknown option: %s", args[index])
	}
}

func parseCIPObjectClasses(value string) ([]uint16, error) {
	return parseICSSelectorNumbers(value, "--object-classes", 65535)
}

func parseIEC104TypeIDs(value string) ([]int, error) {
	items, err := parseIEC104UintCSV(value, "--type-ids", 255)
	if err != nil {
		return nil, err
	}
	ids := make([]int, 0, len(items))
	for _, item := range items {
		if item == 0 {
			return nil, fmt.Errorf("--type-ids values must be in 1..255")
		}
		ids = append(ids, int(item))
	}
	return ids, nil
}

func parseIEC104Classes(value string) ([]string, error) {
	items := strings.Split(value, ",")
	classes := make([]string, 0, len(items))
	for _, item := range items {
		class := strings.TrimSpace(item)
		switch class {
		case "monitor", "control", "system", "unknown":
			classes = append(classes, class)
		default:
			return nil, fmt.Errorf("--classes value %q is invalid (want monitor, control, system, unknown)", class)
		}
	}
	if len(classes) == 0 {
		return nil, fmt.Errorf("--classes requires at least one class")
	}
	return classes, nil
}

func parseIEC104CAs(value string) ([]uint16, error) {
	items, err := parseIEC104UintCSV(value, "--ca", 65535)
	if err != nil {
		return nil, err
	}
	cas := make([]uint16, 0, len(items))
	for _, item := range items {
		if item == 65535 {
			return nil, fmt.Errorf("--ca cannot include broadcast address 65535")
		}
		cas = append(cas, uint16(item))
	}
	return cas, nil
}

func parseIEC104IOARanges(value string) ([]config.IOARange, error) {
	items := strings.Split(value, ",")
	ranges := make([]config.IOARange, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			return nil, fmt.Errorf("--ioa requires decimal addresses or ranges")
		}
		startText, endText, hasEnd := strings.Cut(item, "-")
		start, err := strconv.ParseUint(strings.TrimSpace(startText), 10, 24)
		if err != nil {
			return nil, fmt.Errorf("invalid --ioa address %q: %w", startText, err)
		}
		end := start
		if hasEnd {
			end, err = strconv.ParseUint(strings.TrimSpace(endText), 10, 24)
			if err != nil {
				return nil, fmt.Errorf("invalid --ioa range end %q: %w", endText, err)
			}
		}
		if start > end {
			return nil, fmt.Errorf("invalid --ioa range %d-%d: start is after end", start, end)
		}
		ranges = append(ranges, config.IOARange{Start: uint32(start), End: uint32(end)})
	}
	if len(ranges) == 0 {
		return nil, fmt.Errorf("--ioa requires at least one address or range")
	}
	return ranges, nil
}

func parseIEC104UintCSV(value, flag string, max uint64) ([]uint64, error) {
	items := strings.Split(value, ",")
	values := make([]uint64, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			return nil, fmt.Errorf("%s requires comma-separated decimal values", flag)
		}
		number, err := strconv.ParseUint(item, 10, 16)
		if err != nil || number > max {
			return nil, fmt.Errorf("invalid %s value %q (want 0..%d)", flag, item, max)
		}
		values = append(values, number)
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("%s requires at least one value", flag)
	}
	return values, nil
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
		var dataPlane config.DataPlaneConfig
		if err := api.getJSON(ctx, "/api/v1/dataplane", &dataPlane); err != nil {
			return err
		}
		renderFirewallICSRules(out, rules, dataPlane.DPIMode)
		return nil
	}
}

func renderFirewallICSRules(out io.Writer, rules []config.Rule, globalMode string) {
	t := newTable("ID", "ACTION", "SRC_ZONES", "DST_ZONES", "PROTOCOL", "FUNC_CODES", "UNIT_ID", "ADDRESSES", "OBJECT_CLASSES", "TYPE_IDS", "CLASSES", "CA", "IOA", "R/W", "DIRECTION", "MODE", "MASTERS", "OUTSTATIONS", "GROUPS", "VARIATIONS", "INSTANCES", "ATTRIBUTES", "TAGS", "COT", "ORIGINATORS", "NEGATIVE", "TEST", "SELECT_EXECUTE")
	for _, r := range rules {
		fcs := make([]string, 0, len(r.ICS.FunctionCode))
		for _, fc := range r.ICS.FunctionCode {
			fcs = append(fcs, strconv.Itoa(int(fc)))
		}
		objectClasses := make([]string, 0, len(r.ICS.ObjectClasses))
		for _, class := range r.ICS.ObjectClasses {
			objectClasses = append(objectClasses, strconv.Itoa(int(class)))
		}
		typeIDs := make([]string, 0, len(r.ICS.TypeIDs))
		for _, typeID := range r.ICS.TypeIDs {
			typeIDs = append(typeIDs, strconv.Itoa(typeID))
		}
		cas := make([]string, 0, len(r.ICS.CA))
		for _, ca := range r.ICS.CA {
			cas = append(cas, strconv.Itoa(int(ca)))
		}
		ioa := make([]string, 0, len(r.ICS.IOA))
		for _, addressRange := range r.ICS.IOA {
			if addressRange.Start == addressRange.End {
				ioa = append(ioa, strconv.FormatUint(uint64(addressRange.Start), 10))
			} else {
				ioa = append(ioa, fmt.Sprintf("%d-%d", addressRange.Start, addressRange.End))
			}
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
		effectiveMode := dprules.EffectiveMode(r.ICS.Mode, globalMode)
		mode := fmt.Sprintf("%s (effective: %s)", strings.TrimSpace(r.ICS.Mode), effectiveMode)
		if strings.TrimSpace(r.ICS.Mode) == "" {
			mode = "inherit (" + effectiveMode + ")"
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
			joinCSV(objectClasses),
			joinCSV(typeIDs),
			joinCSV(r.ICS.Classes),
			joinCSV(cas),
			joinCSV(ioa),
			rw,
			firstNonEmpty(r.ICS.Direction, "—"),
			mode,
			selectorCSV(r.ICS.Masters), selectorCSV(r.ICS.Outstations),
			selectorCSV(r.ICS.Groups), selectorCSV(r.ICS.Variations),
			selectorCSV(r.ICS.Instances), selectorCSV(r.ICS.Attributes), joinCSV(r.ICS.Tags),
			selectorCSV(r.ICS.COT), selectorCSV(r.ICS.Originators),
			optionalBool(r.ICS.Negative), optionalBool(r.ICS.Test), firstNonEmpty(r.ICS.SelectExecute, "—"),
		)
	}
	t.render(out)
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
