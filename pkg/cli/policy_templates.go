// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func showPolicyICSTemplatesAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) != 0 {
			return fmt.Errorf("usage: show templates ics")
		}
		var catalog json.RawMessage
		if err := api.getJSON(ctx, "/api/v1/templates/ics", &catalog); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(catalog)
	}
}

func policyICSTemplateAPI(api *API, preview bool) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("usage: preview|apply template ics <name> [--source-zones <csv>] [--dest-zones <csv>] [--ranges <csv>] [--mode <monitor|enforce>]")
		}
		payload := map[string]any{"template": args[0], "preview": preview}
		for i := 1; i < len(args); i += 2 {
			if i+1 >= len(args) {
				return fmt.Errorf("%s requires a value", args[i])
			}
			switch args[i] {
			case "--source-zones":
				payload["sourceZones"] = policyCSV(args[i+1])
			case "--dest-zones":
				payload["destZones"] = policyCSV(args[i+1])
			case "--ranges":
				payload["parameters"] = map[string]string{"ranges": args[i+1]}
			case "--mode":
				if err := validateFirewallICSMode(args[i+1]); err != nil {
					return err
				}
				payload["mode"] = args[i+1]
			default:
				return fmt.Errorf("unknown option: %s", args[i])
			}
		}
		var revisionConfig json.RawMessage
		if preview {
			// Preview is a non-mutating POST and needs no CAS; the API still requires admin.
			var result json.RawMessage
			if err := api.mutateJSON(ctx, http.MethodPost, "/api/v1/templates/ics/apply", payload, &result, nil); err != nil {
				return err
			}
			return json.NewEncoder(out).Encode(result)
		}
		revision, err := api.getConfigJSON(ctx, "/api/v1/config/candidate", &revisionConfig)
		if err != nil {
			return err
		}
		_, err = api.mutateRevisionJSON(ctx, http.MethodPost, "/api/v1/templates/ics/apply", payload, nil, revision, out)
		return err
	}
}
