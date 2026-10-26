// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

// A stored config cannot claim the recovery snapshot's version, so a
// compiled snapshot never passes for the recovery ruleset.
func TestValidateRejectsManagementRecoveryVersion(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Version = ManagementRecoveryVersion
	wantValidateError(t, cfg, "reserved for management recovery")
	cfg.Version = "management-recovery-2"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("ordinary version rejected: %v", err)
	}
}
