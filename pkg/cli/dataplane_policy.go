// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

func setDataPlaneGroupAPI(api *API, key string) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("usage: set dataplane nfqueue-group|nflog-group <0..65535>")
		}
		value, err := strconv.ParseUint(args[0], 10, 16)
		if err != nil {
			return fmt.Errorf("invalid group: %w", err)
		}
		return editPolicyConfig(ctx, api, "/api/v1/dataplane", out, func(current map[string]json.RawMessage) error {
			current[key] = json.RawMessage(strconv.FormatUint(value, 10))
			return nil
		})
	}
}

// Each DPI command changes one setting. Map fields accept comma-separated
// key=value pairs; empty clears the map and otherwise only named keys change.
func setDataPlaneDPIAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 2 {
			return fmt.Errorf("usage: set dataplane dpi enabled|mode|protocols|ics-protocols|ics-parsing|exclusions <value> [reason]")
		}
		key := ""
		var value any
		merge := false
		switch args[0] {
		case "enabled":
			key = "dpiEnabled"
			v, err := parseBoolArg(args[1])
			if err != nil {
				return err
			}
			value = v
		case "mode":
			key = "dpiMode"
			if err := validateFirewallICSMode(args[1]); err != nil {
				return err
			}
			value = args[1]
		case "protocols", "ics-protocols", "ics-parsing":
			key = map[string]string{"protocols": "dpiProtocols", "ics-protocols": "dpiIcsProtocols", "ics-parsing": "dpiIcsParsing"}[args[0]]
			entries := map[string]any{}
			for _, item := range policyCSV(args[1]) {
				name, v, ok := strings.Cut(item, "=")
				if !ok || name == "" {
					return fmt.Errorf("expected protocol=value, got %q", item)
				}
				if args[0] == "ics-parsing" {
					if v != "strict" && v != "tolerant" {
						return fmt.Errorf("parsing must be strict or tolerant")
					}
					entries[name] = v
				} else {
					b, err := parseBoolArg(v)
					if err != nil {
						return err
					}
					entries[name] = b
				}
			}
			value = entries
			merge = len(entries) > 0
		case "exclusions":
			key = "dpiExclusions"
			// Replace the list in one staged edit. Each entry is type:value; colons
			// within IPv6 addresses remain intact. A third argument is a shared note.
			exclusions := []map[string]string{}
			for _, item := range policyCSV(args[1]) {
				kind, v, ok := strings.Cut(item, ":")
				if !ok || v == "" || (kind != "ip" && kind != "cidr" && kind != "domain") {
					return fmt.Errorf("exclusion must be ip:<address>, cidr:<prefix> or domain:<name>")
				}
				entry := map[string]string{"type": kind, "value": v}
				if len(args) == 3 {
					entry["reason"] = args[2]
				}
				exclusions = append(exclusions, entry)
			}
			value = exclusions
		default:
			return fmt.Errorf("unknown DPI setting: %s", args[0])
		}
		if len(args) != 2 && !(args[0] == "exclusions" && len(args) == 3) {
			return fmt.Errorf("unexpected arguments")
		}
		return editPolicyConfig(ctx, api, "/api/v1/dataplane", out, func(current map[string]json.RawMessage) error {
			if merge {
				var existing map[string]any
				if raw := current[key]; raw != nil {
					if err := json.Unmarshal(raw, &existing); err != nil {
						return err
					}
				}
				if existing == nil {
					existing = map[string]any{}
				}
				for k, v := range value.(map[string]any) {
					existing[k] = v
				}
				value = existing
			}
			data, err := json.Marshal(value)
			current[key] = data
			return err
		})
	}
}
