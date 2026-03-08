// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Program manages the lifecycle of eBPF programs (XDP and TC) and their
// associated maps. It is safe for concurrent use after Load() returns.
type Program struct {
	mu sync.Mutex

	// BPF maps
	blockHosts *ebpf.Map // LPM trie of blocked IPs
	blockFlows *ebpf.Map // hash map of blocked 5-tuples
	stats      *ebpf.Map // per-CPU array for packet/byte counters

	// BPF programs
	xdpProg *ebpf.Program
	tcProg  *ebpf.Program

	// Links (attached programs)
	xdpLink link.Link
	tcLink  link.Link

	loaded   bool
	attached bool
	iface    string
}

// NewProgram creates a new Program instance. Call Load() to load the BPF
// programs into the kernel.
func NewProgram() *Program {
	return &Program{}
}

// Load loads the eBPF programs and creates the BPF maps in the kernel.
func (p *Program) Load() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.loaded {
		return errors.New("ebpf: already loaded")
	}

	spec := buildCollectionSpec()

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		return fmt.Errorf("ebpf: load collection: %w", err)
	}

	p.blockHosts = coll.Maps["block_hosts"]
	p.blockFlows = coll.Maps["block_flows"]
	p.stats = coll.Maps["stats"]
	p.xdpProg = coll.Programs["xdp_drop"]
	p.tcProg = coll.Programs["tc_classify"]

	if p.blockHosts == nil || p.blockFlows == nil || p.stats == nil {
		coll.Close()
		return errors.New("ebpf: missing required maps after load")
	}
	if p.xdpProg == nil || p.tcProg == nil {
		coll.Close()
		return errors.New("ebpf: missing required programs after load")
	}

	p.loaded = true
	return nil
}

// Attach attaches the loaded XDP program to the specified network interface.
func (p *Program) Attach(iface string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.loaded {
		return errors.New("ebpf: not loaded")
	}
	if p.attached {
		return fmt.Errorf("ebpf: already attached to %s", p.iface)
	}

	xdpLnk, err := attachXDP(p.xdpProg, iface)
	if err != nil {
		return fmt.Errorf("ebpf: attach xdp to %s: %w", iface, err)
	}
	p.xdpLink = xdpLnk

	tcLnk, err := attachTC(p.tcProg, iface)
	if err != nil {
		// Clean up XDP if TC fails.
		xdpLnk.Close()
		p.xdpLink = nil
		return fmt.Errorf("ebpf: attach tc to %s: %w", iface, err)
	}
	p.tcLink = tcLnk

	p.attached = true
	p.iface = iface
	return nil
}

// Detach detaches the eBPF programs from the network interface.
func (p *Program) Detach() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.attached {
		return nil
	}

	var errs []error
	if p.xdpLink != nil {
		if err := p.xdpLink.Close(); err != nil {
			errs = append(errs, fmt.Errorf("detach xdp: %w", err))
		}
		p.xdpLink = nil
	}
	if p.tcLink != nil {
		if err := p.tcLink.Close(); err != nil {
			errs = append(errs, fmt.Errorf("detach tc: %w", err))
		}
		p.tcLink = nil
	}

	p.attached = false
	p.iface = ""
	return errors.Join(errs...)
}

// Close detaches programs and releases all resources.
func (p *Program) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	var errs []error

	// Detach first (inline to avoid double-lock).
	if p.xdpLink != nil {
		if err := p.xdpLink.Close(); err != nil {
			errs = append(errs, err)
		}
		p.xdpLink = nil
	}
	if p.tcLink != nil {
		if err := p.tcLink.Close(); err != nil {
			errs = append(errs, err)
		}
		p.tcLink = nil
	}
	p.attached = false

	// Close programs.
	if p.xdpProg != nil {
		p.xdpProg.Close()
		p.xdpProg = nil
	}
	if p.tcProg != nil {
		p.tcProg.Close()
		p.tcProg = nil
	}

	// Close maps.
	if p.blockHosts != nil {
		p.blockHosts.Close()
		p.blockHosts = nil
	}
	if p.blockFlows != nil {
		p.blockFlows.Close()
		p.blockFlows = nil
	}
	if p.stats != nil {
		p.stats.Close()
		p.stats = nil
	}

	p.loaded = false
	return errors.Join(errs...)
}

// SyncBlockHosts replaces the contents of the block_hosts BPF map with the
// given set of IPs. Each IP is stored as a /32 prefix in the LPM trie.
func (p *Program) SyncBlockHosts(ips []net.IP) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.loaded || p.blockHosts == nil {
		return errors.New("ebpf: not loaded")
	}

	// Batch delete is not universally supported on LPM tries, so we
	// iterate and delete existing entries, then insert the new set.
	// For a production implementation we would use a swap-map strategy.

	// Delete all existing entries by iterating.
	var key lpmKey
	iter := p.blockHosts.Iterate()
	var keysToDelete []lpmKey
	var val uint32
	for iter.Next(&key, &val) {
		keysToDelete = append(keysToDelete, key)
	}
	for _, k := range keysToDelete {
		_ = p.blockHosts.Delete(&k)
	}

	// Insert new entries.
	one := uint32(1)
	for _, ip := range ips {
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		k := lpmKey{PrefixLen: 32}
		copy(k.Addr[:], v4)
		if err := p.blockHosts.Put(&k, &one); err != nil {
			return fmt.Errorf("ebpf: put block_hosts %s: %w", ip, err)
		}
	}
	return nil
}

// SyncBlockFlows replaces the contents of the block_flows BPF map with the
// given set of flow keys.
func (p *Program) SyncBlockFlows(flows []FlowKey) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.loaded || p.blockFlows == nil {
		return errors.New("ebpf: not loaded")
	}

	// Delete all existing entries.
	var fk bpfFlowKey
	iter := p.blockFlows.Iterate()
	var keysToDelete []bpfFlowKey
	var val uint32
	for iter.Next(&fk, &val) {
		keysToDelete = append(keysToDelete, fk)
	}
	for _, k := range keysToDelete {
		_ = p.blockFlows.Delete(&k)
	}

	// Insert new entries.
	one := uint32(1)
	for _, f := range flows {
		bk, err := flowKeyToBytes(f)
		if err != nil {
			return fmt.Errorf("ebpf: invalid flow key: %w", err)
		}
		if err := p.blockFlows.Put(&bk, &one); err != nil {
			return fmt.Errorf("ebpf: put block_flows: %w", err)
		}
	}
	return nil
}

// ReadStats reads the aggregate packet and byte counters from the per-CPU
// stats map.
func (p *Program) ReadStats() (packets, bytes uint64, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.loaded || p.stats == nil {
		return 0, 0, errors.New("ebpf: not loaded")
	}

	// Stats map has two keys: 0 = packets, 1 = bytes.
	// Each value is a per-CPU uint64 array.
	var pktVals, byteVals []uint64

	k0 := uint32(0)
	if err := p.stats.Lookup(&k0, &pktVals); err != nil {
		return 0, 0, fmt.Errorf("ebpf: read stats packets: %w", err)
	}
	k1 := uint32(1)
	if err := p.stats.Lookup(&k1, &byteVals); err != nil {
		return 0, 0, fmt.Errorf("ebpf: read stats bytes: %w", err)
	}

	for _, v := range pktVals {
		packets += v
	}
	for _, v := range byteVals {
		bytes += v
	}
	return packets, bytes, nil
}

// lpmKey is the key type for the block_hosts LPM trie map.
type lpmKey struct {
	PrefixLen uint32
	Addr      [4]byte
}
