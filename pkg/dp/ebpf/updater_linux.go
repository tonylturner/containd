// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package ebpf

import (
	"fmt"
	"net"
)

// isLoaded returns true if the Program has been successfully loaded.
func isLoaded(p *Program) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.loaded
}

// putBlockHost inserts an IP into the block_hosts BPF map.
func (u *Updater) putBlockHost(ip net.IP) error {
	u.prog.mu.Lock()
	defer u.prog.mu.Unlock()

	if !u.prog.loaded || u.prog.blockHosts == nil {
		return fmt.Errorf("program not loaded")
	}

	v4 := ip.To4()
	if v4 == nil {
		return fmt.Errorf("invalid IPv4")
	}

	k := lpmKey{PrefixLen: 32}
	copy(k.Addr[:], v4)
	one := uint32(1)
	return u.prog.blockHosts.Put(&k, &one)
}

// putBlockFlow inserts a flow key into the block_flows BPF map.
func (u *Updater) putBlockFlow(fk FlowKey) error {
	u.prog.mu.Lock()
	defer u.prog.mu.Unlock()

	if !u.prog.loaded || u.prog.blockFlows == nil {
		return fmt.Errorf("program not loaded")
	}

	bk, err := flowKeyToBytes(fk)
	if err != nil {
		return err
	}
	one := uint32(1)
	return u.prog.blockFlows.Put(&bk, &one)
}
