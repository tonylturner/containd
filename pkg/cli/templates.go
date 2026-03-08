// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cli

import (
	"context"
	"fmt"
	"io"
)

func showTemplatesAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var templates []map[string]any
		if err := api.getJSON(ctx, "/api/v1/templates", &templates); err != nil {
			return err
		}
		if len(templates) == 0 {
			fmt.Fprintln(out, "No templates available.")
			return nil
		}
		for _, t := range templates {
			name, _ := t["name"].(string)
			desc, _ := t["description"].(string)
			fmt.Fprintf(out, "%-25s %s\n", name, desc)
		}
		return nil
	}
}

func applyTemplateAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("usage: apply template <name>")
		}
		payload := map[string]string{"name": args[0]}
		return api.postJSON(ctx, "/api/v1/templates/apply", payload, out)
	}
}
