// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
)

func registerIDSServiceCommands(r *Registry, api *API) {
	const ids = "/api/v1/ids/rules"
	registerServiceFields(r, api, "ids", ids, []serviceField{{"enabled", "enabled", serviceBool}})
	r.RegisterRole("set ids rule enabled", RoleAdmin, setServiceIDSRuleEnabled(api))
	registerServiceCollection(r, api, serviceCollection{
		name: "ids group", endpoint: ids, path: "ruleGroups", keys: []string{"id"},
		fields: []serviceField{
			{"name", "name", serviceText}, {"description", "description", serviceText},
			{"filter", "filter", serviceText}, {"enabled", "enabled", serviceBool},
		}, required: []string{"name"}, defaults: serviceObject{"enabled": json.RawMessage("true")},
	})
}
func setServiceIDSRuleEnabled(api *API) Command {
	c := serviceCollection{name: "ids rule", endpoint: "/api/v1/ids/rules", path: "rules", keys: []string{"id"},
		fields: []serviceField{{"enabled", "enabled", serviceBool}}}
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) != 2 {
			return fmt.Errorf("usage: set ids rule enabled <id> <true|false>")
		}
		return serviceCollectionCommand(api, c, "set")(ctx, out, []string{args[0], "--enabled", args[1]})
	}
}
