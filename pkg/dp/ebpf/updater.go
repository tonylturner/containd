// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package ebpf

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/tonylturner/containd/pkg/dp/enforce"
)

// Updater implements the enforce.Updater interface using eBPF maps for
// fast-path packet filtering. When eBPF is unavailable, it delegates to
// a fallback Updater (typically the nftables-based NftUpdater).
type Updater struct {
	prog     *Program
	fallback enforce.Updater
	enabled  bool
}

// Verify interface compliance at compile time.
var _ enforce.Updater = (*Updater)(nil)

// NewUpdater creates an eBPF-accelerated Updater. If the eBPF Program is nil
// or has not been loaded, all operations fall through to the fallback Updater.
// The fallback may also be nil, in which case operations return an error when
// eBPF is unavailable.
func NewUpdater(prog *Program, fallback enforce.Updater) *Updater {
	enabled := false
	if prog != nil {
		// Try a quick probe: if Load succeeds we know eBPF is available.
		// The caller is expected to have already loaded the program.
		enabled = isLoaded(prog)
	}
	return &Updater{
		prog:     prog,
		fallback: fallback,
		enabled:  enabled,
	}
}

// BlockHostTemp adds an IP to the block_hosts BPF map. If eBPF is not
// available, it delegates to the fallback updater.
//
// Note: BPF maps do not natively support per-entry TTLs. The TTL is tracked
// in userspace and entries are reaped by a periodic sweep (not yet implemented
// in this skeleton). For immediate use, the entry remains until explicitly
// removed or the map is synced.
func (u *Updater) BlockHostTemp(ctx context.Context, ip net.IP, ttl time.Duration) error {
	if !u.enabled || u.prog == nil {
		return u.doFallback(func() error {
			return u.fallback.BlockHostTemp(ctx, ip, ttl)
		})
	}

	v4 := ip.To4()
	if v4 == nil {
		return fmt.Errorf("ebpf updater: invalid IPv4 address")
	}

	if err := u.putBlockHost(v4); err != nil {
		// eBPF update failed; try fallback.
		if u.fallback != nil {
			return u.fallback.BlockHostTemp(ctx, ip, ttl)
		}
		return fmt.Errorf("ebpf updater: block host: %w", err)
	}
	return nil
}

// BlockFlowTemp adds a flow to the block_flows BPF map. If eBPF is not
// available, it delegates to the fallback updater.
func (u *Updater) BlockFlowTemp(ctx context.Context, srcIP, dstIP net.IP, proto string, dport string, ttl time.Duration) error {
	if !u.enabled || u.prog == nil {
		return u.doFallback(func() error {
			return u.fallback.BlockFlowTemp(ctx, srcIP, dstIP, proto, dport, ttl)
		})
	}

	protoNum, err := ProtoFromString(proto)
	if err != nil {
		return fmt.Errorf("ebpf updater: %w", err)
	}

	dp, err := strconv.Atoi(dport)
	if err != nil || dp < 1 || dp > 65535 {
		return fmt.Errorf("ebpf updater: invalid dport %q", dport)
	}

	fk := FlowKey{
		SrcIP: srcIP,
		DstIP: dstIP,
		Proto: protoNum,
		DPort: uint16(dp),
	}

	if err := u.putBlockFlow(fk); err != nil {
		if u.fallback != nil {
			return u.fallback.BlockFlowTemp(ctx, srcIP, dstIP, proto, dport, ttl)
		}
		return fmt.Errorf("ebpf updater: block flow: %w", err)
	}
	return nil
}

// doFallback calls fn if the fallback updater is available.
func (u *Updater) doFallback(fn func() error) error {
	if u.fallback != nil {
		return fn()
	}
	return fmt.Errorf("ebpf updater: ebpf not available and no fallback configured")
}

// IsEnabled reports whether the eBPF fast path is active.
func (u *Updater) IsEnabled() bool {
	return u.enabled
}
