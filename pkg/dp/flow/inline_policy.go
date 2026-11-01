// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"sync/atomic"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// InlinePolicy is receive-time policy evidence, independent of asynchronous
// correlation identity. It is immutable after publication. An empty Context
// still records an inline packet with missing dependent evidence.
type InlinePolicy struct {
	Context rules.EvalContext
	Service Key
	Reply   bool
}

// InlinePolicySlot stays copyable in flow snapshots, like ConnectionSlot.
type InlinePolicySlot struct{ pointer *atomic.Pointer[InlinePolicy] }

func (s InlinePolicySlot) Load() *InlinePolicy {
	if s.pointer == nil {
		return nil
	}
	return s.pointer.Load()
}

func (s *InlinePolicySlot) Store(p *InlinePolicy) {
	if s.pointer == nil {
		s.pointer = new(atomic.Pointer[InlinePolicy])
	}
	s.pointer.Store(p)
}
