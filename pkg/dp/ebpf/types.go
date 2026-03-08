// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"
)

// FlowKey represents a 5-tuple flow identifier for the block_flows BPF map.
type FlowKey struct {
	SrcIP net.IP
	DstIP net.IP
	Proto uint8  // 6 = TCP, 17 = UDP
	DPort uint16 // destination port in host byte order
}

// bpfFlowKey is the binary representation written into the BPF map.
// It must match the C struct layout used in the BPF program.
type bpfFlowKey struct {
	SrcAddr uint32 // network byte order
	DstAddr uint32 // network byte order
	Proto   uint8
	_       [1]byte // padding
	DPort   uint16  // network byte order
}

func flowKeyToBytes(fk FlowKey) (bpfFlowKey, error) {
	src := fk.SrcIP.To4()
	dst := fk.DstIP.To4()
	if src == nil || dst == nil {
		return bpfFlowKey{}, fmt.Errorf("invalid IPv4 addresses in flow key")
	}
	return bpfFlowKey{
		SrcAddr: binary.BigEndian.Uint32(src),
		DstAddr: binary.BigEndian.Uint32(dst),
		Proto:   fk.Proto,
		DPort:   swap16(fk.DPort),
	}, nil
}

func swap16(v uint16) uint16 {
	return (v>>8)&0xff | (v&0xff)<<8
}

// ProtoFromString converts a protocol name to its IP protocol number.
func ProtoFromString(proto string) (uint8, error) {
	switch proto {
	case "tcp":
		return 6, nil
	case "udp":
		return 17, nil
	default:
		return 0, fmt.Errorf("unsupported protocol %q", proto)
	}
}

// Stats holds packet and byte counters read from the BPF stats map.
type Stats struct {
	Packets uint64
	Bytes   uint64
}
