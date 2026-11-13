// SPDX-License-Identifier: Apache-2.0

package limits

import "testing"

func TestOwnerResources(t *testing.T) {
	a, b := NewResources(nil, nil), NewResources(nil, nil)
	if a.Budget == b.Budget || a.Ledger == b.Ledger || a.Budget.Status().Limit != DefaultMaxInspectionBytes {
		t.Fatal("missing private finite resources")
	}
	c := NewResources(a.Budget, a.Ledger)
	if c != a {
		t.Fatal("injected resources replaced")
	}
}
