// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"io"
)

// PATCH sends only changed fields, based on the revision of the inspected interface.
func patchExistingInterface(ctx context.Context, api *API, name string, patch map[string]any, out io.Writer) error {
	var ifaces []map[string]any
	revision, err := api.getConfigJSON(ctx, "/api/v1/interfaces", &ifaces)
	if err != nil {
		return err
	}
	for _, iface := range ifaces {
		if iface["name"] != name {
			continue
		}
		_, err := api.mutateRevisionJSON(ctx, "PATCH", "/api/v1/interfaces/"+urlEscape(name), patch, nil, revision, out)
		return err
	}
	return fmt.Errorf("interface not found: %s", name)
}
