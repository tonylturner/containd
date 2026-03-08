// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package ebpf

import (
	ciliumebpf "github.com/cilium/ebpf"
)

// buildCollectionSpec assembles the full eBPF CollectionSpec from the
// individual XDP and TC program/map specifications.
func buildCollectionSpec() *ciliumebpf.CollectionSpec {
	maps := make(map[string]*ciliumebpf.MapSpec)

	// Merge XDP maps.
	for k, v := range xdpMapSpecs() {
		maps[k] = v
	}
	// Merge TC maps.
	for k, v := range tcMapSpecs() {
		maps[k] = v
	}

	return &ciliumebpf.CollectionSpec{
		Maps: maps,
		Programs: map[string]*ciliumebpf.ProgramSpec{
			"xdp_drop":    xdpProgSpec(),
			"tc_classify": tcProgSpec(),
		},
	}
}
