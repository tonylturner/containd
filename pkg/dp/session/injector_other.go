// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build !linux

package session

// NewInjector reports ErrUnsupportedPlatform: raw IPv4 injection needs
// Linux.
func NewInjector() (Injector, error) {
	return nil, ErrUnsupportedPlatform
}
