// SPDX-License-Identifier: Apache-2.0
package itdpi

import (
	"strings"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/limits"
)

func (d *HTTPDecoder) admit(st *flow.State, v dpi.StreamView) (*httpStream, error) {
	d.resources = limits.NewResources(d.resources.Budget, d.resources.Ledger)
	prefix, identity := metadataConnectionParts(st, v)
	memory := decoderMemory(d.resources, v.Enforcing, int(limits.DecoderMetadataBytes)+len(v.Session)+len(prefix)+len(identity))
	if memory == nil {
		return nil, dpi.StateLimitError(d.resources, v.Enforcing, "http", v.Base)
	}
	connection := prefix + identity
	peer := d.connections[connection]
	if peer == nil {
		owner := decoderMemory(d.resources, v.Enforcing, int(limits.DecoderMetadataBytes)+len(connection))
		if owner == nil {
			memory.Release()
			return nil, dpi.StateLimitError(d.resources, v.Enforcing, "http", v.Base)
		}
		peer = &httpConnection{memory: owner, resources: d.resources, streams: make(map[httpStreamKey]*httpStream)}
		d.connections[strings.Clone(connection)] = peer
	}
	d.serial++
	key := httpStreamKey{strings.Clone(v.Session), v.Dir}
	s := &httpStream{id: d.serial, key: key, connection: connection, peer: peer,
		memory: memory, enforcing: v.Enforcing}
	d.streams[key], peer.streams[key] = s, s
	return s, nil
}

func (s *httpStream) dropH2() {
	if s.h2 != nil {
		s.h2.release()
		s.h2 = nil
	}
}

func (s *httpStream) stateLimit(r limits.Resources, base int64) error {
	if s.failure == nil {
		s.failure = dpi.StateLimitError(r, s.enforcing, "http", base)
		s.clearFraming()
		s.dropH2()
		s.peer.uncertain = true
	}
	return s.failure
}

func (c *httpConnection) clearRequests() {
	for i := range c.methods {
		r := c.methods[i].memory
		c.methods[i] = httpRequest{}
		if r != nil {
			r.Release()
		}
	}
	c.methods = nil
	if c.arrayMemory != nil {
		c.arrayMemory.Release()
		c.arrayMemory = nil
	}
}
