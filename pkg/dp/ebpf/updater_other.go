// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build !linux

package ebpf

import (
	"fmt"
	"net"
)

// isLoaded always returns false on non-Linux platforms.
func isLoaded(_ *Program) bool { return false }

// putBlockHost is a no-op stub on non-Linux platforms.
func (u *Updater) putBlockHost(ip net.IP) error {
	return fmt.Errorf("ebpf: not supported on this platform")
}

// putBlockFlow is a no-op stub on non-Linux platforms.
func (u *Updater) putBlockFlow(fk FlowKey) error {
	return fmt.Errorf("ebpf: not supported on this platform")
}
