// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build !linux

package httpapi

func diskStatfs(_ string) diskStats {
	return diskStats{}
}
