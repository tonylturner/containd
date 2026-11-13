// SPDX-License-Identifier: Apache-2.0
package dpi

import (
	"time"

	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/limits"
)

func (r *reassembler) admit(key string, pos position, keep, enforcing bool, now time.Time) *StreamError {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.streams[key] != nil {
		return nil
	}
	s, err := r.allocate(key, enforcing)
	if err != nil {
		return err
	}
	s.strict, s.mode, s.seq0, s.keep, s.verify, s.lastUpdate = true, pos.kind, pos.seq, keep, enforcing, now
	r.streams[key] = s
	r.activeStreams++
	return nil
}

func (r *reassembler) contains(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.streams[key] != nil
}

func (r *reassembler) SetResources(resources limits.Resources) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.streams) != 0 {
		panic("dpi: cannot replace resources of a live reassembler")
	}
	r.resources = limits.NewResources(resources.Budget, resources.Ledger)
}

func (r *reassembler) allocate(key string, enforcing bool) (*stream, *StreamError) {
	class := limits.ClassObserve
	if enforcing {
		class = limits.ClassEnforce
	}
	mem := flow.NewInspectionMemory(r.resources, class, limits.CategoryStream)
	if !mem.Reserve(int(limits.StreamMetadataBytes) + oooIndexBytes + len(key)) {
		return nil, StateLimitError(r.resources, enforcing, "", 0)
	}
	s := &stream{memory: mem, resources: r.resources, enforcing: enforcing}
	s.ooo = s.segments[:0]
	return s, nil
}

func (s *stream) allocationFailure() *StreamError {
	if se, ok := s.failed.(*StreamError); ok && se.Kind == StreamStateLimit {
		return se
	}
	se := StateLimitError(s.resources, s.enforcing, "", s.end())
	s.failed = se
	return se
}

func (s *stream) clearBytes() {
	n := s.bufCharge + s.histCharge
	for i := range s.ooo {
		n += cap(s.ooo[i].data)
		s.ooo[i] = oooSegment{}
	}
	s.buf, s.hist = nil, nil
	s.ooo = s.segments[:0]
	s.bufCharge, s.histCharge = 0, 0
	s.memory.Refund(n)
}

func (s *stream) appendBuffer(data []byte) *StreamError {
	if len(data) == 0 {
		return nil
	}
	n := len(s.buf) + len(data)
	if !s.memory.Reserve(n) {
		return s.allocationFailure()
	}
	buf := make([]byte, n)
	copy(buf, s.buf)
	copy(buf[len(s.buf):], data)
	old := s.bufCharge
	s.buf, s.bufCharge = buf, n
	s.memory.Refund(old)
	return nil
}

func (s *stream) replaceHistory(n, maxSize int) *StreamError {
	total := len(s.hist) + n
	size := min(total, maxSize)
	if !s.memory.Reserve(size) {
		return s.allocationFailure()
	}
	hist := make([]byte, size)
	discard := total - size
	oldStart := min(discard, len(s.hist))
	copied := copy(hist, s.hist[oldStart:])
	copy(hist[copied:], s.buf[max(0, discard-len(s.hist)):n])
	old := s.histCharge
	s.hist, s.histCharge = hist, size
	s.memory.Refund(old)
	return nil
}
