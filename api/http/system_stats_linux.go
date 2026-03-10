// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package httpapi

import "syscall"

func diskStatfs(path string) diskStats {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return diskStats{}
	}
	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bavail * uint64(stat.Bsize)
	used := total - free
	var pct float64
	if total > 0 {
		pct = float64(used) / float64(total) * 100
	}
	return diskStats{
		TotalBytes:     total,
		UsedBytes:      used,
		AvailableBytes: free,
		UsagePercent:   pct,
	}
}
