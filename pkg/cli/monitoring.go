// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package cli

import (
	"fmt"
	"io"
)

// monitoringUnavailable preserves the fetch error while making unknown state
// visible to console clients that render command output separately from errors.
func monitoringUnavailable(out io.Writer, subject string, err error) error {
	if out != nil {
		fmt.Fprintf(out, "%s unavailable (state unknown).\n", subject)
	}
	return fmt.Errorf("%s unavailable: %w", subject, err)
}
