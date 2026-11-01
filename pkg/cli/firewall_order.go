// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func parseRulePosition(args []string) (any, error) {
	if len(args) == 1 && (args[0] == "top" || args[0] == "bottom") {
		return args[0], nil
	}
	if len(args) == 2 && (args[0] == "before" || args[0] == "after") && args[1] != "" {
		return map[string]string{args[0]: args[1]}, nil
	}
	return nil, fmt.Errorf("position must be top|bottom|before <id>|after <id>")
}

func moveFirewallRuleAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 2 {
			return fmt.Errorf("usage: move firewall rule <id> top|bottom|before <id>|after <id>")
		}
		position, err := parseRulePosition(args[1:])
		if err != nil {
			return err
		}
		return api.postJSON(ctx, "/api/v1/firewall/rules/"+url.PathEscape(args[0])+"/move", map[string]any{"position": position}, out)
	}
}

func setFirewallRuleAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 2 {
			return fmt.Errorf("usage: add firewall rule <id> <action> [src_zone] [dst_zone] [top|bottom|before <id>|after <id>]")
		}
		rule := config.Rule{ID: args[0], Action: config.Action(strings.ToUpper(args[1]))}
		position := any("bottom")
		end := len(args)
		// Position is a suffix; zone names before it retain their existing
		// positional meaning.
		for i := 2; i < len(args); i++ {
			switch args[i] {
			case "top", "bottom", "before", "after":
				var err error
				position, err = parseRulePosition(args[i:])
				if err != nil {
					return err
				}
				end = i
			}
			if end != len(args) {
				break
			}
		}
		if end > 4 {
			return fmt.Errorf("too many zones")
		}
		if end > 2 {
			rule.SourceZones = []string{args[2]}
		}
		if end > 3 {
			rule.DestZones = []string{args[3]}
		}
		return api.postJSON(ctx, "/api/v1/firewall/rules", struct {
			config.Rule
			Position any `json:"position"`
		}{rule, position}, out)
	}
}
