// SPDX-License-Identifier: Apache-2.0

package limits

// Resources are construction-time inspection accounting dependencies. Owners
// retain this value, never mutate the budget capacity, and share it only within
// a configuration generation. The ledger alone may outlive that generation.
type Resources struct {
	Budget *Budget
	Ledger *Ledger
}

// NewResources resolves missing dependencies to private finite accounting.
func NewResources(budget *Budget, ledger *Ledger) Resources {
	if budget == nil {
		budget = NewBudget(DefaultMaxInspectionBytes)
	}
	if ledger == nil {
		ledger = NewLedger(nil)
	}
	return Resources{Budget: budget, Ledger: ledger}
}
