// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build !linux

package cli

import "fmt"

func listIPv4Routes() ([]ipv4Route, error) {
	return nil, fmt.Errorf("show ip route is only supported on linux")
}
