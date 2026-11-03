// SPDX-License-Identifier: Apache-2.0

package config

import "fmt"

type ProfileOverride struct {
	Field     string `json:"field"`
	Saved     string `json:"saved"`
	Effective string `json:"effective"`
}

// TLSProfileFields is embedded in TLS status responses. Values describe the
// effective next-start configuration, not the currently bound sockets.
// Source is "profile" only when a saved/default value was overridden; otherwise
// "config" for explicit saved values or "default". Saved is present only for
// overrides and contains the resolved saved value (nil config booleans default
// to true). Fingerprints are omitted when no corresponding leaf is available.
type TLSProfileFields struct {
	HTTPEnabled                 bool   `json:"httpEnabled"`
	HTTPEnabledSource           string `json:"httpEnabledSource"`
	HTTPEnabledSaved            *bool  `json:"httpEnabledSaved,omitempty"`
	HTTPSEnabled                bool   `json:"httpsEnabled"`
	HTTPSEnabledSource          string `json:"httpsEnabledSource"`
	HTTPSEnabledSaved           *bool  `json:"httpsEnabledSaved,omitempty"`
	HSTSEnabled                 bool   `json:"hstsEnabled"`
	HSTSEnabledSource           string `json:"hstsEnabledSource"`
	HSTSEnabledSaved            *bool  `json:"hstsEnabledSaved,omitempty"`
	ServedCertFingerprintSHA256 string `json:"servedCertFingerprintSHA256,omitempty"`
	CertFingerprintSHA256       string `json:"certFingerprintSHA256,omitempty"`
}

// SSHProfileFields is the shell-mode portion of SSH status responses. Saved is
// the literal saved string, including "" for the appliance default, and is
// present only when the resolved saved mode differs from the effective mode.
// API sources are "profile", "environment", "config" or "default"; runtime/CLI
// sources retain ResolveSSHShellMode's more descriptive vocabulary.
// Unlike TLS, strict SSH always reports the profile source, even when saved
// intent agrees, because the profile also blocks the CLI's shell escape.
type SSHProfileFields struct {
	ShellMode       string  `json:"shellMode"`
	ShellModeSource string  `json:"shellModeSource"`
	ShellModeSaved  *string `json:"shellModeSaved,omitempty"`
}

// ProfileStatusFields freezes the reusable status composition; it does not
// register a route. Existing TLS and SSH responses embed the corresponding
// fields directly; aggregate status can use these named sections.
type ProfileStatusFields struct {
	TLS TLSProfileFields `json:"tls"`
	SSH SSHProfileFields `json:"ssh"`
}

// ProjectProfile makes a read-only runtime view. The top-level config and all
// modified pointer values are copied; unrelated collections remain shared and
// must not be mutated by consumers. Nil input remains nil.
func ProjectProfile(cfg *Config, strict bool) (*Config, []ProfileOverride) {
	if cfg == nil {
		return nil, nil
	}
	effective := *cfg
	if !strict {
		return &effective, nil
	}
	var overrides []ProfileOverride
	savedShell, _ := ResolveSSHShellMode(cfg.System.SSH.ShellMode, "")
	if savedShell != SSHShellModeAppliance {
		overrides = append(overrides, ProfileOverride{"system.ssh.shellMode", cfg.System.SSH.ShellMode, SSHShellModeAppliance})
	}
	effective.System.SSH.ShellMode = SSHShellModeAppliance
	for _, field := range []struct {
		name string
		dst  **bool
		want bool
	}{
		{"system.mgmt.enableHTTPS", &effective.System.Mgmt.EnableHTTPS, true},
		{"system.mgmt.enableHSTS", &effective.System.Mgmt.EnableHSTS, true},
		{"system.mgmt.enableHTTP", &effective.System.Mgmt.EnableHTTP, false},
	} {
		saved := profileBool(*field.dst)
		if saved != field.want {
			overrides = append(overrides, ProfileOverride{field.name, fmt.Sprint(saved), fmt.Sprint(field.want)})
		}
		value := field.want
		*field.dst = &value
	}
	return &effective, overrides
}

func profileBool(value *bool) bool { return value == nil || *value }

// ValidateProfileWrite rejects newly introduced weak saved intent. Baseline
// must be the unprojected running config, never the previous candidate. HTTP
// enablement is intentionally not rejected: its universal default is true.
func ValidateProfileWrite(baseline, next *Config, strict bool) error {
	if !strict || next == nil {
		return nil
	}
	if baseline == nil {
		baseline = &Config{}
	}
	weakShell := func(c *Config) bool {
		mode, _ := ResolveSSHShellMode(c.System.SSH.ShellMode, "")
		return mode == SSHShellModeLinux
	}
	if weakShell(next) && !weakShell(baseline) {
		return fmt.Errorf("ssh.shellMode %q: the Linux shell is training-only (CONTAIND_PROFILE=strict)", next.System.SSH.ShellMode)
	}
	if !profileBool(next.System.Mgmt.EnableHTTPS) && profileBool(baseline.System.Mgmt.EnableHTTPS) {
		return fmt.Errorf("mgmt.enableHTTPS false: HTTPS is mandatory (CONTAIND_PROFILE=strict)")
	}
	if !profileBool(next.System.Mgmt.EnableHSTS) && profileBool(baseline.System.Mgmt.EnableHSTS) {
		return fmt.Errorf("mgmt.enableHSTS false: HSTS is mandatory (CONTAIND_PROFILE=strict)")
	}
	return nil
}
