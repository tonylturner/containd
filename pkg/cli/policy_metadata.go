// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// editPolicyConfig retains fields not owned by a focused command, and ties the
// write to the same revision as the read, without retrying stale edits.
func editPolicyConfig(ctx context.Context, api *API, path string, out io.Writer, edit func(map[string]json.RawMessage) error) error {
	var current map[string]json.RawMessage
	revision, err := api.getConfigJSON(ctx, path, &current)
	if err != nil {
		return err
	}
	if err := edit(current); err != nil {
		return err
	}
	return api.saveJSON(ctx, path, current, revision, out)
}

func setFirewallDefaultAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("usage: set firewall default <ALLOW|DENY>")
		}
		action := strings.ToUpper(args[0])
		if action != "ALLOW" && action != "DENY" {
			return fmt.Errorf("default action must be ALLOW or DENY")
		}
		if out != nil {
			fmt.Fprintln(out, "Warning: the default action affects all unmatched traffic after commit; review management reachability and use commit confirmed.")
		}
		return editPolicyConfig(ctx, api, "/api/v1/config/candidate", out, func(current map[string]json.RawMessage) error {
			var firewall map[string]json.RawMessage
			if err := json.Unmarshal(current["firewall"], &firewall); err != nil {
				return err
			}
			if firewall == nil {
				return fmt.Errorf("candidate has no firewall configuration")
			}
			data, err := json.Marshal(action)
			if err != nil {
				return err
			}
			firewall["defaultAction"] = data
			data, err = json.Marshal(firewall)
			current["firewall"] = data
			return err
		})
	}
}

func setZoneConsequenceAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) != 2 {
			return fmt.Errorf("usage: set zone consequence <name> <consequence> (use '' to clear)")
		}
		return api.patchJSON(ctx, "/api/v1/zones/"+url.PathEscape(args[0]), map[string]string{"consequence": args[1]}, out)
	}
}

func setAssetHostnamesAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) != 2 {
			return fmt.Errorf("usage: set asset hostnames <id> <comma-separated hostnames> (use '' to clear)")
		}
		var assets []map[string]json.RawMessage
		revision, err := api.getConfigJSON(ctx, "/api/v1/assets", &assets)
		if err != nil {
			return err
		}
		for _, asset := range assets {
			var id string
			if err := json.Unmarshal(asset["id"], &id); err != nil {
				return err
			}
			if id != args[0] {
				continue
			}
			// Asset PATCH is a replacement, not a merge. Preserve all other fields.
			asset["hostnames"], err = json.Marshal(policyCSV(args[1]))
			if err != nil {
				return err
			}
			_, err = api.mutateRevisionJSON(ctx, http.MethodPatch, "/api/v1/assets/"+url.PathEscape(id), asset, nil, revision, out)
			return err
		}
		return fmt.Errorf("asset %q not found", args[0])
	}
}
