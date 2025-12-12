package cli

import (
	"context"
	"io"
)

func showServicesStatus(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var payload map[string]any
		if err := api.getJSON(ctx, "/api/v1/services/status", &payload); err != nil {
			return err
		}
		return printJSON(out, payload)
	}
}

