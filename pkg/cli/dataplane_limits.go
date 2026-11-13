// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"

	"github.com/tonylturner/containd/pkg/cp/config"
)

func setDataPlaneLimitsAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) != 2 {
			return fmt.Errorf("usage: set dataplane limits maxFlows|maxTopTalkers|maxInspectionBytes <value> (0 selects default)")
		}
		switch args[0] {
		case "maxFlows", "maxTopTalkers", "maxInspectionBytes":
		default:
			return fmt.Errorf("unknown dataplane limit %q", args[0])
		}
		value, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil {
			return fmt.Errorf("%s: expected integer: %w", args[0], err)
		}
		return editPolicyConfig(ctx, api, "/api/v1/dataplane", out, func(current map[string]json.RawMessage) error {
			var stored map[string]json.RawMessage
			if raw := current["limits"]; raw != nil {
				if err := json.Unmarshal(raw, &stored); err != nil {
					return err
				}
			}
			if stored == nil {
				stored = map[string]json.RawMessage{}
			}
			stored[args[0]] = json.RawMessage(strconv.FormatInt(value, 10))
			data, err := json.Marshal(stored)
			if err != nil {
				return err
			}
			var fields config.DataPlaneLimits
			if err := json.Unmarshal(data, &fields); err != nil {
				return err
			}
			if err := fields.Effective().Validate(); err != nil {
				return err
			}
			current["limits"] = data
			return nil
		})
	}
}
