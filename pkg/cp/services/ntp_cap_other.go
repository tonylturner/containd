// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build !linux

package services

// hasSysTimeCap is a no-op on non-Linux platforms; NTP supervision is
// Linux-only anyway, but this avoids build failures.
func hasSysTimeCap() bool { return false }
