// SPDX-License-Identifier: Apache-2.0
package synth

import (
	"testing"

	"github.com/tonylturner/containd/pkg/dp/ics"
)

func TestRemovedProtocolScenarios(t *testing.T) {
	for _, scenario := range scenarios {
		if ics.Removed(scenario.proto) {
			t.Fatalf("retired synthetic scenario: %s", scenario.proto)
		}
	}
}
