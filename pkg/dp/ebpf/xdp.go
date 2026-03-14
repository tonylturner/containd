// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package ebpf

import (
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
)

// xdpMapSpecs returns the BPF map specifications used by the XDP program.
func xdpMapSpecs() map[string]*ebpf.MapSpec {
	return map[string]*ebpf.MapSpec{
		"block_hosts": {
			Name:       "block_hosts",
			Type:       ebpf.LPMTrie,
			KeySize:    8, // 4-byte prefix length + 4-byte IPv4 addr
			ValueSize:  4, // uint32 (1 = blocked)
			MaxEntries: 16384,
			Flags:      1, // BPF_F_NO_PREALLOC required for LPM trie
		},
		"stats": {
			Name:       "stats",
			Type:       ebpf.PerCPUArray,
			KeySize:    4, // uint32 index
			ValueSize:  8, // uint64 counter
			MaxEntries: 2, // 0 = packets, 1 = bytes
		},
	}
}

// xdpProgSpec returns the BPF program specification for the XDP drop program.
// The program is a minimal placeholder that passes all traffic (XDP_PASS).
// In production, the actual BPF bytecode would perform LPM lookups against
// the block_hosts map and return XDP_DROP for matching packets.
func xdpProgSpec() *ebpf.ProgramSpec {
	return &ebpf.ProgramSpec{
		Name:    "xdp_drop",
		Type:    ebpf.XDP,
		License: "Apache-2.0",
		Instructions: asm.Instructions{
			// r0 = XDP_PASS (2)
			asm.Mov.Imm(asm.R0, 2),
			asm.Return(),
		},
	}
}

// attachXDP attaches an XDP program to the named network interface.
func attachXDP(prog *ebpf.Program, iface string) (link.Link, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	return link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: ifi.Index,
	})
}
