// SPDX-License-Identifier: Apache-2.0

package config

import "fmt"

// ManagementRecoveryVersion is the snapshot version of the fail-closed
// management recovery ruleset. The engine reports the version it applied,
// and management recognizes recovery by it, so a stored config can never
// carry it: compiled snapshots take their version from the config.
const ManagementRecoveryVersion = "management-recovery"

func validateVersion(v string) error {
	if v == ManagementRecoveryVersion {
		return fmt.Errorf("version %q is reserved for management recovery", v)
	}
	return nil
}
