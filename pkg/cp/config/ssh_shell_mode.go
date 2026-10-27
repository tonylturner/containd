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

// EnvSSHShellMode overrides system.ssh.shellMode when it is not empty.
const EnvSSHShellMode = "CONTAIND_SSH_SHELL_MODE"

// Sources of the shell mode SSH runs.
const (
	SSHShellModeSourceEnvironment = "environment (" + EnvSSHShellMode + ")"
	SSHShellModeSourceConfig      = "config"
	SSHShellModeSourceDefault     = "default"
)

// ResolveSSHShellMode returns the shell mode SSH runs and its source. A
// non-empty env selects linux when it is linux in any letter case and the
// appliance CLI otherwise. Without it the saved mode applies; an empty
// saved mode is the appliance CLI.
func ResolveSSHShellMode(saved, env string) (mode, source string) {
	if env = strings.TrimSpace(env); env != "" {
		if strings.EqualFold(env, SSHShellModeLinux) {
			return SSHShellModeLinux, SSHShellModeSourceEnvironment
		}
		return SSHShellModeAppliance, SSHShellModeSourceEnvironment
	}
	switch {
	case saved == "":
		return SSHShellModeAppliance, SSHShellModeSourceDefault
	case strings.EqualFold(saved, SSHShellModeLinux):
		return SSHShellModeLinux, SSHShellModeSourceConfig
	default:
		return SSHShellModeAppliance, SSHShellModeSourceConfig
	}
}
