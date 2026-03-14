// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build !linux

package ebpf

import (
	"errors"
	"net"
)

var errNotSupported = errors.New("ebpf: not supported on this platform")

// Program is a stub on non-Linux platforms.
type Program struct{}

// NewProgram returns a stub Program.
func NewProgram() *Program { return &Program{} }

// Load returns an unsupported error on non-Linux platforms.
func (p *Program) Load() error { return errNotSupported }

// Attach returns an unsupported error on non-Linux platforms.
func (p *Program) Attach(iface string) error { return errNotSupported }

// Detach returns an unsupported error on non-Linux platforms.
func (p *Program) Detach() error { return errNotSupported }

// Close returns nil on non-Linux platforms.
func (p *Program) Close() error { return nil }

// SyncBlockHosts returns an unsupported error on non-Linux platforms.
func (p *Program) SyncBlockHosts(ips []net.IP) error { return errNotSupported }

// SyncBlockFlows returns an unsupported error on non-Linux platforms.
func (p *Program) SyncBlockFlows(flows []FlowKey) error { return errNotSupported }

// ReadStats returns an unsupported error on non-Linux platforms.
func (p *Program) ReadStats() (packets, bytes uint64, err error) { return 0, 0, errNotSupported }
