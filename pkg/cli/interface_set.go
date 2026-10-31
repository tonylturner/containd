// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"io"
)

// PATCH preserves omitted fields. Send the complete current interface with
// explicit clearing values, retaining empty arrays when clearing addresses.
func patchExistingInterface(ctx context.Context, api *API, name string, patch map[string]any, out io.Writer) error {
	var ifaces []map[string]any
	if err := api.getConfigJSON(ctx, "/api/v1/interfaces", &ifaces); err != nil {
		return err
	}
	for _, iface := range ifaces {
		if iface["name"] != name {
			continue
		}
		for key, value := range patch {
			iface[key] = value
		}
		return api.patchJSON(ctx, "/api/v1/interfaces/"+urlEscape(name), iface, out)
	}
	return fmt.Errorf("interface not found: %s", name)
}
