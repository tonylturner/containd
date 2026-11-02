// SPDX-License-Identifier: Apache-2.0
//go:build !linux

package services

import (
	"context"
	"errors"
	"os/exec"
	"strings"
)

// Non-Linux development hosts can prove absence, but cannot safely bind an
// orphan signal to a process identity. Never claim teardown if one is found.
func stopPriorTraffic(ctx context.Context, base, name string) error {
	data, err := exec.CommandContext(ctx, "ps", "-ax", "-o", "command=").Output()
	if err != nil {
		return errors.New("traffic process inventory unavailable")
	}
	for _, line := range strings.Split(string(data), "\n") {
		for _, path := range trafficConfigPaths(base, name) {
			for _, flag := range []string{" -c ", " --config "} {
				if strings.Contains(line+" ", flag+path+" ") {
					return errors.New("orphan traffic teardown requires Linux")
				}
			}
		}
	}
	return nil
}
