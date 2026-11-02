// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func setFirewallRuleAPI(api *API) Command    { return policyRulePatchAPI(api, false) }
func setFirewallICSRuleAPI(api *API) Command { return policyRulePatchAPI(api, true) }

func policyRulePatchAPI(api *API, ics bool) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 3 {
			return fmt.Errorf("usage: set firewall rule|ics-rule <id> --<field> <value> [more fields]")
		}
		patch, err := parsePolicyRulePatch(args[1:], ics)
		if err != nil {
			return err
		}
		// The generic rule PATCH merges fields (including ICS selectors). The ICS
		// alias replaces the entire rule, so it cannot safely express a partial edit.
		return api.patchJSON(ctx, "/api/v1/firewall/rules/"+url.PathEscape(args[0]), patch, out)
	}
}

func parsePolicyRulePatch(args []string, ics bool) (map[string]any, error) {
	patch := map[string]any{}
	for i := 0; i < len(args); i += 2 {
		if i+1 >= len(args) || !strings.HasPrefix(args[i], "--") {
			return nil, fmt.Errorf("expected --field value, got %q", args[i])
		}
		flag, value := args[i], args[i+1]
		switch flag {
		case "--action":
			patch["action"] = strings.ToUpper(value)
		case "--description", "--tag":
			patch[strings.TrimPrefix(flag, "--")] = value
		case "--src-zone", "--source-zones":
			patch["sourceZones"] = policyCSV(value)
		case "--dst-zone", "--dest-zones":
			patch["destZones"] = policyCSV(value)
		case "--sources", "--destinations", "--identities", "--via-forwards":
			key := strings.TrimPrefix(flag, "--")
			if flag == "--via-forwards" {
				key = "viaForwards"
			}
			patch[key] = policyCSV(value)
		case "--protocols":
			protocols := []config.Protocol{}
			for _, item := range policyCSV(value) {
				name, port, _ := strings.Cut(item, ":")
				protocols = append(protocols, config.Protocol{Name: name, Port: port})
			}
			patch["protocols"] = protocols
		case "--log":
			v, err := parseBoolArg(value)
			if err != nil {
				return nil, err
			}
			patch["log"] = v
		case "--schedule":
			if value != "none" {
				return nil, fmt.Errorf("--schedule accepts none; use --schedule-days/start/end/timezone to edit")
			}
			patch["schedule"] = nil
		case "--schedule-days", "--schedule-start", "--schedule-end", "--schedule-timezone":
			schedule, ok := patch["schedule"].(map[string]any)
			if !ok {
				schedule = map[string]any{}
				patch["schedule"] = schedule
			}
			switch flag {
			case "--schedule-days":
				schedule["daysOfWeek"] = policyCSV(value)
			case "--schedule-start":
				schedule["startTime"] = value
			case "--schedule-end":
				schedule["endTime"] = value
			case "--schedule-timezone":
				schedule["timezone"] = value
			}
		case "--rate-limit":
			if value == "none" {
				patch["rateLimit"] = nil
				continue
			}
			pps, burst, hasBurst := strings.Cut(value, ":")
			p, err := strconv.ParseUint(pps, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid --rate-limit: %w", err)
			}
			rate := config.RateLimitConfig{PacketsPerSecond: uint32(p)}
			if hasBurst {
				b, err := strconv.ParseUint(burst, 10, 32)
				if err != nil {
					return nil, fmt.Errorf("invalid burst: %w", err)
				}
				rate.Burst = uint32(b)
			}
			patch["rateLimit"] = map[string]uint32{"packetsPerSecond": rate.PacketsPerSecond, "burst": rate.Burst}
		default:
			if !ics {
				return nil, fmt.Errorf("unknown option: %s", flag)
			}
			key, v, err := policyICSField(flag, value)
			if err != nil {
				return nil, err
			}
			predicate, ok := patch["ics"].(map[string]any)
			if !ok {
				predicate = map[string]any{}
				patch["ics"] = predicate
			}
			predicate[key] = v
		}
	}
	return patch, nil
}

var policyICSKeys = map[string]string{
	"--ics-protocol":       "protocol",
	"--function-code":      "functionCode",
	"--object-classes":     "objectClasses",
	"--unit-id":            "unitId",
	"--addresses":          "addresses",
	"--read-only":          "readOnly",
	"--write-only":         "writeOnly",
	"--mode":               "mode",
	"--type-ids":           "typeIds",
	"--classes":            "classes",
	"--ca":                 "ca",
	"--ioa":                "ioa",
	"--direction":          "direction",
	"--masters":            "masters",
	"--outstations":        "outstations",
	"--groups":             "groups",
	"--variations":         "variations",
	"--instances":          "instances",
	"--attributes":         "attributes",
	"--tags":               "tags",
	"--cot":                "cot",
	"--originators":        "originators",
	"--negative":           "negative",
	"--test":               "test",
	"--select-execute":     "selectExecute",
	"--command-states":     "commandStates",
	"--command-qualifiers": "commandQualifiers",
}

func policyICSField(flag, value string) (string, any, error) {
	key, ok := policyICSKeys[flag]
	if !ok {
		return "", nil, fmt.Errorf("unknown option: %s", flag)
	}
	// Empty values explicitly clear a selector; omission preserves it.
	if value == "" {
		return key, nil, nil
	}
	if flag == "--ics-protocol" {
		return key, value, nil
	}
	if flag == "--read-only" || flag == "--write-only" {
		v, err := parseBoolArg(value)
		return key, v, err
	}
	var rule config.Rule
	if _, err := applyFirewallICSRuleArg(&rule, []string{flag, value}, 0); err != nil {
		return "", nil, err
	}
	data, err := json.Marshal(rule.ICS)
	if err != nil {
		return "", nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return "", nil, err
	}
	// Fields with omitempty still need an explicit zero in a patch.
	v := fields[key]
	if v == nil {
		v = json.RawMessage("null")
	}
	return key, v, nil
}

// policyCSV makes an explicit empty list distinct from an omitted field.
func policyCSV(value string) []string {
	items := splitCSV(value)
	if items == nil {
		return []string{}
	}
	return items
}
