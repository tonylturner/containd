// SPDX-License-Identifier: Apache-2.0
package config

import (
	"fmt"
	"strings"
)

// SSH shell modes select what an interactive SSH login opens. An empty
// system.ssh.shellMode means the appliance CLI.
const (
	SSHShellModeAppliance = "appliance"
	SSHShellModeLinux     = "linux"
)

func validateSSHShellMode(mode string) error {
	switch mode {
	case "", SSHShellModeAppliance, SSHShellModeLinux:
		return nil
	}
	return fmt.Errorf("ssh.shellMode %q: use appliance or linux", mode)
}

// normalizeStoredSSHShellMode maps a stored shellMode that earlier releases
// saved without validation to the mode they ran: linux in any letter case
// runs the Linux shell, every other value the appliance CLI.
func normalizeStoredSSHShellMode(ssh *SSHConfig) {
	switch {
	case ssh.ShellMode == "":
	case strings.EqualFold(ssh.ShellMode, SSHShellModeLinux):
		ssh.ShellMode = SSHShellModeLinux
	default:
		ssh.ShellMode = SSHShellModeAppliance
	}
}
