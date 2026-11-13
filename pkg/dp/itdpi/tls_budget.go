// SPDX-License-Identifier: Apache-2.0
package itdpi

import (
	"strings"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/limits"
)

func (d *TLSDecoder) admit(st *flow.State, v dpi.StreamView) (*tlsStream, error) {
	d.resources = limits.NewResources(d.resources.Budget, d.resources.Ledger)
	prefix, identity := metadataConnectionParts(st, v)
	memory := decoderMemory(d.resources, v.Enforcing, int(limits.DecoderMetadataBytes)+len(v.Session)+len(prefix)+len(identity))
	if memory == nil {
		return nil, dpi.StateLimitError(d.resources, v.Enforcing, "tls", v.Base)
	}
	connection := prefix + identity
	peer := d.connections[connection]
	if peer == nil {
		owner := decoderMemory(d.resources, v.Enforcing, int(limits.DecoderMetadataBytes)+len(connection))
		if owner == nil {
			memory.Release()
			return nil, dpi.StateLimitError(d.resources, v.Enforcing, "tls", v.Base)
		}
		peer = &tlsConnection{memory: owner}
		d.connections[strings.Clone(connection)] = peer
	}
	peer.refs++
	s := &tlsStream{memory: memory, enforcing: v.Enforcing, connection: connection, peer: peer}
	d.streams[tlsStreamKey{strings.Clone(v.Session), v.Dir}] = s
	return s, nil
}

func (s *tlsStream) clearHello() {
	size := cap(s.hello)
	s.hello = nil
	s.memory.Refund(size)
}
