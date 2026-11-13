// SPDX-License-Identifier: Apache-2.0
package dpi

import "github.com/tonylturner/containd/pkg/dp/limits"

// ResourceOwner is implemented by decoders retaining inspection allocations.
// Managers install the same generation resources before publishing an owner.
type ResourceOwner interface {
	SetResources(limits.Resources)
}

type bindingID struct{ flow, stream string }

// InspectionResources returns the immutable generation accounting dependencies.
// Observation wrappers use the manager's authority, never a second budget.
func (m *Manager) InspectionResources() limits.Resources {
	m.streamMu.Lock()
	defer m.streamMu.Unlock()
	return m.resources
}

func (m *Manager) SetResources(r limits.Resources) {
	m.streamMu.Lock()
	defer m.streamMu.Unlock()
	if len(m.bindings) != 0 {
		panic("dpi: cannot replace resources of a live manager")
	}
	m.resources = limits.NewResources(r.Budget, r.Ledger)
	m.reassembler.SetResources(m.resources)
	for _, d := range m.decoders {
		if owner, ok := d.(ResourceOwner); ok {
			owner.SetResources(m.resources)
		}
	}
	for _, d := range m.observation {
		if owner, ok := d.(ResourceOwner); ok {
			owner.SetResources(m.resources)
		}
	}
}

// bind reserves both the directional flow's side maps and a session binding,
// if present, before dispatch writes any registry. Partial admission rolls back.
func (m *Manager) bind(flowID, key string, enforcing bool) *StreamError {
	ids := [2]bindingID{{flowID, flowID}, {flowID, key}}
	var added [2]bindingID
	count := 0
	for i, id := range ids {
		if i == 1 && key == flowID || m.bindings[id] != nil {
			continue
		}
		class := limits.ClassObserve
		if enforcing {
			class = limits.ClassEnforce
		}
		lease, ok := m.resources.Budget.Reserve(class, limits.CategoryStream,
			limits.BindingMetadataBytes+int64(len(id.flow)+len(id.stream)))
		if !ok {
			for _, rollback := range added[:count] {
				m.unbind(rollback)
			}
			return StateLimitError(m.resources, enforcing, "", 0)
		}
		m.bindings[id] = lease
		added[count] = id
		count++
	}
	m.ownSelection(flowID, key)
	return nil
}

func (m *Manager) unbind(id bindingID) {
	if lease := m.bindings[id]; lease != nil {
		delete(m.bindings, id)
		lease.Release()
	}
}
