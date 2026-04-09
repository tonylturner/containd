// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package services

import "golang.org/x/sys/unix"

// hasSysTimeCap probes whether the process can adjust the system clock.
// Chrony requires CAP_SYS_TIME; without it, chronyd exits immediately.
func hasSysTimeCap() bool {
	// ADJ_SETOFFSET (0x0100) is a write operation that requires CAP_SYS_TIME.
	// We use a zero offset so even if it succeeds, the clock is not changed.
	var buf unix.Timex
	buf.Modes = 0x0100 // ADJ_SETOFFSET
	_, err := unix.Adjtimex(&buf)
	return err == nil
}
