// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func previewFirewallICSRuleAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		rule, err := parseFirewallICSRuleArgs(args)
		if err != nil {
			return err
		}
		var response json.RawMessage
		// A preview is not a candidate mutation and must not send a revision
		// or print a staged/committed success message.
		if _, err := api.mutateRevisionJSON(ctx, http.MethodPost, "/api/v1/firewall/rules/preview", rule, &response, "", nil); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(response)
	}
}

func previewFirewallRulesetAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) != 0 {
			return fmt.Errorf("usage: preview firewall ruleset")
		}
		var response json.RawMessage
		if err := api.getJSON(ctx, "/api/v1/dataplane/ruleset", &response); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(response)
	}
}
