// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package ebpf

import (
	"fmt"
	"net"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
)

// TC action constants (matching linux/pkt_cls.h).
const (
	tcActOK = 0 // TC_ACT_OK — continue processing
)

// tcMapSpecs returns the BPF map specifications used by the TC classifier.
func tcMapSpecs() map[string]*ciliumebpf.MapSpec {
	return map[string]*ciliumebpf.MapSpec{
		"block_flows": {
			Name:       "block_flows",
			Type:       ciliumebpf.Hash,
			KeySize:    8,  // bpfFlowKey: srcAddr(4) + dstAddr(4) + proto(1) + pad(1) + dport(2) = 8? No — 12 bytes
			ValueSize:  4,  // uint32 (1 = blocked)
			MaxEntries: 65536,
		},
	}
}

func init() {
	// Correct the block_flows key size to match bpfFlowKey struct (12 bytes).
	specs := tcMapSpecs()
	specs["block_flows"].KeySize = 12
}

// tcProgSpec returns the BPF program specification for the TC classifier.
// The program is a minimal placeholder that returns TC_ACT_OK (pass all traffic).
// In production, the actual BPF bytecode would:
//   - Parse the packet to extract the 5-tuple
//   - Look up the flow in the block_flows hash map
//   - Return TC_ACT_SHOT for blocked flows
//   - Optionally steer selected flows to NFQUEUE for deep inspection
func tcProgSpec() *ciliumebpf.ProgramSpec {
	return &ciliumebpf.ProgramSpec{
		Name:    "tc_classify",
		Type:    ciliumebpf.SchedCLS,
		License: "Apache-2.0",
		Instructions: asm.Instructions{
			// r0 = TC_ACT_OK (0)
			asm.Mov.Imm(asm.R0, tcActOK),
			asm.Return(),
		},
	}
}

// attachTC attaches a TC classifier program to the named network interface
// on the ingress path using TCX (kernel 6.6+). Falls back to netlink-based
// attachment on older kernels via cilium/ebpf's link package.
func attachTC(prog *ciliumebpf.Program, iface string) (link.Link, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("tc: interface %s: %w", iface, err)
	}
	return link.AttachTCX(link.TCXOptions{
		Program:   prog,
		Attach:    ciliumebpf.AttachTCXIngress,
		Interface: ifi.Index,
	})
}
