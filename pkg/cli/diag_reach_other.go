// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build !linux

package cli

import "syscall"

func bindToDeviceControl(dev string) func(network, address string, c syscall.RawConn) error {
	// SO_BINDTODEVICE is Linux-only. Non-Linux builds (developer machines) still compile,
	// but interface binding is not enforced.
	return nil
}
