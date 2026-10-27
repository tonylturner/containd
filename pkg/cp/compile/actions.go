// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"github.com/tonylturner/containd/pkg/cp/config"
	dprules "github.com/tonylturner/containd/pkg/dp/rules"
)

// rateLimit copies a rule's policer. A zero burst means one second of
// packets, so the snapshot always carries the effective bucket depth.
func rateLimit(rl *config.RateLimitConfig) *dprules.RateLimit {
	if rl == nil {
		return nil
	}
	burst := rl.Burst
	if burst == 0 {
		burst = rl.PacketsPerSecond
	}
	return &dprules.RateLimit{PacketsPerSecond: rl.PacketsPerSecond, Burst: burst}
}
