// SPDX-License-Identifier: Apache-2.0
//go:build linux

package capture

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"

	nfqueue "github.com/florianl/go-nfqueue/v2"
)

func queueMetadata(a nfqueue.Attribute) *QueueMetadata {
	m := &QueueMetadata{}
	if a.Hook != nil {
		m.Hook, m.HasHook = *a.Hook, true
	}
	if a.InDev != nil {
		m.InDev = *a.InDev
		m.IngressDevice = deviceName(m.InDev)
	}
	if a.OutDev != nil {
		m.OutDev = *a.OutDev
		m.EgressDevice = deviceName(m.OutDev)
	}
	if a.Ct != nil {
		ct, err := decodeQueueConntrack(*a.Ct, a.CtInfo)
		if err != nil {
			m.ConntrackError = err.Error()
		} else {
			m.Conntrack = ct
		}
	}
	return m
}

func deviceName(index uint32) string {
	if index == 0 {
		return ""
	}
	iface, err := net.InterfaceByIndex(int(index))
	if err != nil {
		return ""
	}
	return iface.Name
}

func queueAttrs(data []byte) (map[uint16][]byte, error) {
	out := make(map[uint16][]byte)
	for len(data) > 0 {
		if len(data) < 4 {
			return nil, fmt.Errorf("short queued conntrack attribute")
		}
		n := int(binary.NativeEndian.Uint16(data))
		aligned := (n + 3) &^ 3
		if n < 4 || aligned > len(data) {
			return nil, fmt.Errorf("invalid queued conntrack attribute length")
		}
		typ := binary.NativeEndian.Uint16(data[2:]) & 0x3fff
		if _, duplicate := out[typ]; duplicate {
			return nil, fmt.Errorf("duplicate conntrack attribute %d", typ)
		}
		out[typ] = data[4:n]
		data = data[aligned:]
	}
	return out, nil
}

// NFQA_CT contains nested CTA_* attributes without an nfgenmsg header.
func decodeQueueConntrack(data []byte, info *uint32) (*QueueConntrack, error) {
	a, err := queueAttrs(data)
	if err != nil {
		return nil, err
	}
	ct := &QueueConntrack{}
	if info != nil {
		if *info > 5 { // IP_CT_NUMBER and IP_CT_UNTRACKED are not tracked directions.
			return nil, fmt.Errorf("untracked or invalid conntrack info %d", *info)
		}
		ct.DirectionKnown, ct.IsReply = true, *info >= 3
	}
	for _, field := range []struct {
		id  uint16
		dst *uint32
		has *bool
	}{{8, &ct.Mark, &ct.HasMark}, {3, &ct.Status, &ct.HasStatus}} {
		if b, ok := a[field.id]; ok {
			if len(b) != 4 {
				return nil, fmt.Errorf("invalid conntrack attribute %d length", field.id)
			}
			*field.dst, *field.has = binary.BigEndian.Uint32(b), true
		}
	}
	if ct.Original, err = decodeQueueTuple(a[1]); err != nil {
		return nil, err
	}
	if ct.Reply, err = decodeQueueTuple(a[2]); err != nil {
		return nil, err
	}
	return ct, nil
}

func decodeQueueTuple(data []byte) (QueueTuple, error) {
	var t QueueTuple
	a, err := queueAttrs(data)
	if err != nil {
		return t, err
	}
	ip, err := queueAttrs(a[1]) // CTA_TUPLE_IP
	if err != nil {
		return t, err
	}
	proto, err := queueAttrs(a[2]) // CTA_TUPLE_PROTO
	if err != nil {
		return t, err
	}
	if b, ok := proto[1]; ok {
		if len(b) != 1 {
			return t, fmt.Errorf("invalid conntrack protocol")
		}
		t.Protocol, t.HasProtocol = b[0], true
	}
	for _, endpoint := range []struct {
		v4, v6, port uint16
		dst          *netip.AddrPort
	}{{1, 3, 2, &t.Source}, {2, 4, 3, &t.Destination}} {
		var addr netip.Addr
		if b, ok := ip[endpoint.v4]; ok {
			if len(b) != 4 {
				return t, fmt.Errorf("invalid conntrack IPv4 address")
			}
			addr = netip.AddrFrom4([4]byte(b))
		}
		if b, ok := ip[endpoint.v6]; ok {
			if addr.IsValid() || len(b) != 16 {
				return t, fmt.Errorf("invalid conntrack address family")
			}
			addr = netip.AddrFrom16([16]byte(b))
		}
		if b, ok := proto[endpoint.port]; ok {
			if len(b) != 2 {
				return t, fmt.Errorf("invalid conntrack port")
			}
			if addr.IsValid() && t.HasProtocol && (t.Protocol == 6 || t.Protocol == 17) {
				*endpoint.dst = netip.AddrPortFrom(addr, binary.BigEndian.Uint16(b))
			}
		}
	}
	return t, nil
}
