// SPDX-License-Identifier: Apache-2.0
package engineapi

import (
	"time"

	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
)

func UnknownProtection(id string) dpengine.ProtectionStatus {
	return dpengine.ProtectionStatus{ApplyID: id, State: "unknown", ObservedAt: time.Now().UTC(), Components: []dpengine.ProtectionComponent{}, Effects: []dpengine.ProtectionEffect{}}
}

// NormalizeProtection never substitutes a different application's observation.
func NormalizeProtection(st dpengine.ProtectionStatus, expectedID string) dpengine.ProtectionStatus {
	if st.BootID == "" || st.ObservedAt.IsZero() || expectedID != "" && st.ApplyID != expectedID {
		return UnknownProtection(expectedID)
	}
	switch st.State {
	case "pending", "protecting", "degraded", "failed", "disabled", "unknown":
	default:
		return UnknownProtection(expectedID)
	}
	if st.Components == nil {
		st.Components = []dpengine.ProtectionComponent{}
	}
	if st.Effects == nil {
		st.Effects = []dpengine.ProtectionEffect{}
	}
	return st
}
