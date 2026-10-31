// SPDX-License-Identifier: Apache-2.0

package flow

import (
	"net"
	"net/netip"

	"github.com/tonylturner/containd/pkg/dp/conntrack"
)

// MapKey is a comparable, directional tuple with the same equality as Hash.
// IPv4 and IPv4-mapped IPv6 normalize to the same address. Malformed net.IP
// values retain their distinct public spelling instead of collapsing to the
// invalid netip address. No address slices or packet buffers are retained.
type MapKey struct {
	src, dst         mapAddress
	srcPort, dstPort uint16
	proto            uint8
	dir              Direction
}

type mapAddress struct {
	addr      netip.Addr
	malformed string
}

func addressKey(ip net.IP) mapAddress {
	if addr, ok := netip.AddrFromSlice(ip); ok {
		return mapAddress{addr: addr.Unmap()}
	}
	return mapAddress{malformed: ip.String()}
}

func (k Key) MapKey() MapKey {
	return MapKey{addressKey(k.SrcIP), addressKey(k.DstIP), k.SrcPort, k.DstPort, k.Proto, k.Dir}
}

// TupleMapKey avoids materializing net.IP slices for conntrack lookups.
func TupleMapKey(t conntrack.Tuple, dir Direction) MapKey {
	address := func(addr netip.Addr) mapAddress {
		if !addr.IsValid() {
			return mapAddress{malformed: "<nil>"}
		}
		return mapAddress{addr: addr.WithZone("").Unmap()}
	}
	return MapKey{address(t.Source.Addr()), address(t.Destination.Addr()),
		t.Source.Port(), t.Destination.Port(), t.Protocol, dir}
}

// Bidirectional removes opener orientation and wire direction for tuple
// tombstones and decision serialization. Its ordering is private, not flowId.
func (k MapKey) Bidirectional() MapKey {
	order := k.src.addr.Compare(k.dst.addr)
	if order == 0 {
		switch {
		case k.src.malformed < k.dst.malformed:
			order = -1
		case k.src.malformed > k.dst.malformed:
			order = 1
		}
	}
	if order > 0 || order == 0 && k.srcPort > k.dstPort {
		k.src, k.dst = k.dst, k.src
		k.srcPort, k.dstPort = k.dstPort, k.srcPort
	}
	k.dir = DirForward
	return k
}
