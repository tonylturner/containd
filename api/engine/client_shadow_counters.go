// SPDX-License-Identifier: Apache-2.0
package engineapi

import (
	"context"

	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
)

func (c *HTTPClient) ShadowCounters(ctx context.Context) (dpengine.ShadowCounters, error) {
	var out dpengine.ShadowCounters
	err := c.getJSON(ctx, "/internal/firewall/shadow-counters", "engine shadow counters status", &out)
	return out, err
}
