// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"unsafe"

	"github.com/tonylturner/containd/pkg/dp/limits"
)

// Grow retained pointer/marker storage geometrically, charging the actual
// capacity only when needed. Replacement credit precedes copying, and a
// transaction retains old credit until its backing stores can be retired.
func pairGrow[T any, K protocolPairKey, S any](items *[]T, lease **limits.Lease, resources limits.Resources, class limits.Class, journal *pairJournal[K, S]) bool {
	if len(*items) < cap(*items) || len(*items) == pairSessionCap {
		return true
	}
	capacity := min(pairSessionCap, max(1, 2*cap(*items)))
	var item T
	replacement, ok := resources.Budget.Reserve(class, limits.CategoryPairing, int64(capacity)*int64(unsafe.Sizeof(item)))
	if !ok {
		return false
	}
	next := make([]T, len(*items), capacity)
	copy(next, *items)
	if journal != nil {
		journal.storageCreated = append(journal.storageCreated, replacement)
		if *lease != nil {
			journal.storageRemoved = append(journal.storageRemoved, *lease)
		}
	} else if *lease != nil {
		(*lease).Release()
	}
	*items, *lease = next, replacement
	return true
}
