// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
)

const savedListenerNotice = "Listener settings: saved configuration (not environment overrides or live socket state)."

// savedListeners resolves the listeners cfg saves, defaults included. An API
// client does not see the management process's environment, so environment
// overrides are not applied.
func savedListeners(cfg *config.Config) config.ManagementListeners {
	return config.ResolveManagementListeners(cfg, func(string) string { return "" })
}

func showRunningConfig(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var cfg config.Config
		if err := api.getJSON(ctx, "/api/v1/config/export", &cfg); err != nil {
			return err
		}
		return printJSON(out, cfg)
	}
}

func showRunningConfigRedacted(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var cfg config.Config
		if err := api.getJSON(ctx, "/api/v1/config/export?redacted=1", &cfg); err != nil {
			return err
		}
		return printJSON(out, cfg)
	}
}

func showCandidateConfig(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var cfg config.Config
		if err := api.getJSON(ctx, "/api/v1/config/candidate", &cfg); err != nil {
			return err
		}
		return printJSON(out, cfg)
	}
}

func showDiff(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var payload map[string]any
		revision, err := api.getConfigJSON(ctx, "/api/v1/config/diff", &payload)
		if err != nil {
			return err
		}
		fmt.Fprintln(out, "Revision:", revision)
		return printJSON(out, payload)
	}
}

// showSystem shows saved system settings, health, and the SSH shell mode the
// appliance runs. A client without the appliance's store runs the command on
// the appliance, so its own environment never stands in for the appliance's.
func showSystem(store config.Store, api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if store == nil {
			return executeOnAppliance(ctx, api, out, "show system")
		}
		type health struct {
			Status    string `json:"status"`
			Component string `json:"component"`
			Build     string `json:"build,omitempty"`
			Time      string `json:"time,omitempty"`
		}
		var h health
		healthErr := api.getJSON(ctx, "/api/v1/health", &h)

		var cfg config.Config
		configErr := api.getJSON(ctx, "/api/v1/config", &cfg)

		if out == nil {
			return errors.Join(healthErr, configErr)
		}
		if configErr != nil {
			configErr = monitoringUnavailable(out, "System configuration", configErr)
		} else {
			fmt.Fprintf(out, "hostname: %s\n", cfg.System.Hostname)
			fmt.Fprintln(out, savedListenerNotice)
			listeners := savedListeners(&cfg)
			fmt.Fprintf(out, "mgmt.http_enabled: %s\n", yesNoStr(listeners.HTTP.Enabled))
			fmt.Fprintf(out, "mgmt.https_enabled: %s\n", yesNoStr(listeners.HTTPS.Enabled))
			fmt.Fprintf(out, "mgmt.http_listen: %s\n", listeners.HTTP.Addr)
			fmt.Fprintf(out, "mgmt.https_listen: %s\n", listeners.HTTPS.Addr)
			fmt.Fprintf(out, "mgmt.redirect_http_to_https: %s\n", yesNoStr(boolDefault(cfg.System.Mgmt.RedirectHTTPToHTTPS, false)))
			fmt.Fprintf(out, "mgmt.hsts: %s\n", yesNoStr(boolDefault(cfg.System.Mgmt.EnableHSTS, true)))
			if cfg.System.Mgmt.HSTSMaxAgeSeconds > 0 {
				fmt.Fprintf(out, "mgmt.hsts_max_age_seconds: %d\n", cfg.System.Mgmt.HSTSMaxAgeSeconds)
			}
			if cfg.System.Mgmt.TLSCertFile != "" {
				fmt.Fprintf(out, "mgmt.tls_cert_file: %s\n", cfg.System.Mgmt.TLSCertFile)
			}
			if cfg.System.Mgmt.TLSKeyFile != "" {
				fmt.Fprintf(out, "mgmt.tls_key_file: %s\n", cfg.System.Mgmt.TLSKeyFile)
			}
			if cfg.System.Mgmt.TrustedCAFile != "" {
				fmt.Fprintf(out, "mgmt.trusted_ca_file: %s\n", cfg.System.Mgmt.TrustedCAFile)
			}
			fmt.Fprintf(out, "ssh.listen: %s\n", listeners.SSH.Addr)
			if cfg.System.SSH.AuthorizedKeysDir != "" {
				fmt.Fprintf(out, "ssh.authorized_keys_dir: %s\n", cfg.System.SSH.AuthorizedKeysDir)
			}
			fmt.Fprintf(out, "ssh.allow_password: %s\n", sshPasswordSetting(cfg.System.SSH.AllowPassword))
			configErr = showSSHShellMode(ctx, store, out, cfg.System.SSH.ShellMode)
		}
		if healthErr != nil {
			healthErr = monitoringUnavailable(out, "System health", healthErr)
		} else {
			fmt.Fprintf(out, "component: %s\n", h.Component)
			if h.Build != "" {
				fmt.Fprintf(out, "build: %s\n", h.Build)
			}
			if h.Time != "" {
				if t, err := time.Parse(time.RFC3339Nano, h.Time); err == nil {
					fmt.Fprintf(out, "time: %s\n", t.UTC().Format(time.RFC3339Nano))
				} else {
					fmt.Fprintf(out, "time: %s\n", h.Time)
				}
			}
		}
		return errors.Join(healthErr, configErr)
	}
}

func showMgmtListeners(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var cfg config.Config
		if err := api.getJSON(ctx, "/api/v1/config", &cfg); err != nil {
			return monitoringUnavailable(out, "Management listener configuration", err)
		}
		if out == nil {
			return nil
		}

		fmt.Fprintln(out, savedListenerNotice)
		listeners := savedListeners(&cfg)
		kvTable(out, map[string]string{
			"http_enabled":            yesNoStr(listeners.HTTP.Enabled),
			"https_enabled":           yesNoStr(listeners.HTTPS.Enabled),
			"http_listen":             listeners.HTTP.Addr,
			"https_listen":            listeners.HTTPS.Addr,
			"redirect_http_to_https":  yesNoStr(boolDefault(cfg.System.Mgmt.RedirectHTTPToHTTPS, false)),
			"hsts":                    yesNoStr(boolDefault(cfg.System.Mgmt.EnableHSTS, true)),
			"hsts_max_age_seconds":    fmt.Sprintf("%d", max(0, cfg.System.Mgmt.HSTSMaxAgeSeconds)),
			"tls_cert_file":           firstNonEmpty(cfg.System.Mgmt.TLSCertFile, "—"),
			"tls_key_file":            firstNonEmpty(cfg.System.Mgmt.TLSKeyFile, "—"),
			"trusted_ca_file":         firstNonEmpty(cfg.System.Mgmt.TrustedCAFile, "—"),
			"ssh_listen":              listeners.SSH.Addr,
			"ssh_allow_password":      sshPasswordSetting(cfg.System.SSH.AllowPassword),
			"ssh_authorized_keys_dir": firstNonEmpty(cfg.System.SSH.AuthorizedKeysDir, "—"),
		})

		fmt.Fprintln(out)
		t := newTable("IFACE", "DEVICE", "MGMT", "HTTP", "HTTPS", "SSH")
		for _, iface := range cfg.Interfaces {
			t.addRow(
				iface.Name,
				firstNonEmpty(iface.Device, "—"),
				yesNoStr(boolDefault(iface.Access.Mgmt, true)),
				yesNoStr(boolDefault(iface.Access.HTTP, true)),
				yesNoStr(boolDefault(iface.Access.HTTPS, true)),
				yesNoStr(boolDefault(iface.Access.SSH, true)),
			)
		}
		t.render(out)
		return nil
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func setSystemHostnameAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("usage: set system hostname <name>")
		}
		cfg, revision, err := loadCandidateConfig(ctx, api)
		if err != nil {
			return err
		}
		cfg.System.Hostname = args[0]
		return api.saveJSON(ctx, "/api/v1/config/candidate", cfg, revision, out)
	}
}

func setSystemMgmtListenAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("usage: set system mgmt listen <addr>")
		}
		cfg, revision, err := loadCandidateConfig(ctx, api)
		if err != nil {
			return err
		}
		cfg.System.Mgmt.HTTPListenAddr = args[0]
		cfg.System.Mgmt.ListenAddr = ""
		return api.saveJSON(ctx, "/api/v1/config/candidate", cfg, revision, out)
	}
}

func setSystemMgmtHTTPListenAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("usage: set system mgmt http listen <addr>")
		}
		cfg, revision, err := loadCandidateConfig(ctx, api)
		if err != nil {
			return err
		}
		cfg.System.Mgmt.HTTPListenAddr = args[0]
		cfg.System.Mgmt.ListenAddr = ""
		return api.saveJSON(ctx, "/api/v1/config/candidate", cfg, revision, out)
	}
}

func setSystemMgmtHTTPSListenAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("usage: set system mgmt https listen <addr>")
		}
		cfg, revision, err := loadCandidateConfig(ctx, api)
		if err != nil {
			return err
		}
		cfg.System.Mgmt.HTTPSListenAddr = args[0]
		return api.saveJSON(ctx, "/api/v1/config/candidate", cfg, revision, out)
	}
}

func setSystemMgmtEnableHTTPAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("usage: set system mgmt http enable <true|false>")
		}
		v, err := parseBoolArg(args[0])
		if err != nil {
			return err
		}
		cfg, revision, err := loadCandidateConfig(ctx, api)
		if err != nil {
			return err
		}
		cfg.System.Mgmt.EnableHTTP = &v
		return api.saveJSON(ctx, "/api/v1/config/candidate", cfg, revision, out)
	}
}

func setSystemMgmtEnableHTTPSAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("usage: set system mgmt https enable <true|false>")
		}
		v, err := parseBoolArg(args[0])
		if err != nil {
			return err
		}
		cfg, revision, err := loadCandidateConfig(ctx, api)
		if err != nil {
			return err
		}
		cfg.System.Mgmt.EnableHTTPS = &v
		return api.saveJSON(ctx, "/api/v1/config/candidate", cfg, revision, out)
	}
}

func setSystemMgmtRedirectHTTPToHTTPSAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("usage: set system mgmt redirect-http-to-https <true|false>")
		}
		v, err := parseBoolArg(args[0])
		if err != nil {
			return err
		}
		cfg, revision, err := loadCandidateConfig(ctx, api)
		if err != nil {
			return err
		}
		cfg.System.Mgmt.RedirectHTTPToHTTPS = &v
		return api.saveJSON(ctx, "/api/v1/config/candidate", cfg, revision, out)
	}
}

func setSystemMgmtHSTSAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("usage: set system mgmt hsts <true|false> [max_age_seconds]")
		}
		enabled, err := parseBoolArg(args[0])
		if err != nil {
			return err
		}
		maxAge := 31536000
		if len(args) >= 2 {
			if v, err := strconv.Atoi(strings.TrimSpace(args[1])); err == nil && v > 0 {
				maxAge = v
			}
		}
		cfg, revision, err := loadCandidateConfig(ctx, api)
		if err != nil {
			return err
		}
		cfg.System.Mgmt.EnableHSTS = &enabled
		if enabled {
			cfg.System.Mgmt.HSTSMaxAgeSeconds = maxAge
		}
		return api.saveJSON(ctx, "/api/v1/config/candidate", cfg, revision, out)
	}
}

func setSystemSSHListenAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("usage: set system ssh listen <addr>")
		}
		cfg, revision, err := loadCandidateConfig(ctx, api)
		if err != nil {
			return err
		}
		cfg.System.SSH.ListenAddr = args[0]
		return api.saveJSON(ctx, "/api/v1/config/candidate", cfg, revision, out)
	}
}

func setSystemSSHAllowPasswordAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("usage: set system ssh allow-password <true|false>")
		}
		v := strings.ToLower(strings.TrimSpace(args[0]))
		var enabled bool
		switch v {
		case "1", "true", "yes", "on":
			enabled = true
		case "0", "false", "no", "off":
			enabled = false
		default:
			return fmt.Errorf("invalid allow-password value %q", args[0])
		}
		cfg, revision, err := loadCandidateConfig(ctx, api)
		if err != nil {
			return err
		}
		cfg.System.SSH.AllowPassword = &enabled
		return api.saveJSON(ctx, "/api/v1/config/candidate", cfg, revision, out)
	}
}

func setSystemSSHAuthorizedKeysDirAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("usage: set system ssh authorized-keys-dir <dir>")
		}
		cfg, revision, err := loadCandidateConfig(ctx, api)
		if err != nil {
			return err
		}
		cfg.System.SSH.AuthorizedKeysDir = args[0]
		return api.saveJSON(ctx, "/api/v1/config/candidate", cfg, revision, out)
	}
}

func setSystemSSHBannerAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("usage: set system ssh banner <text>")
		}
		cfg, revision, err := loadCandidateConfig(ctx, api)
		if err != nil {
			return err
		}
		cfg.System.SSH.Banner = strings.Join(args, " ")
		return api.saveJSON(ctx, "/api/v1/config/candidate", cfg, revision, out)
	}
}

func setSystemSSHHostKeyRotationAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("usage: set system ssh host-key-rotation <days>")
		}
		days, err := strconv.Atoi(strings.TrimSpace(args[0]))
		if err != nil || days < 0 || days > config.MaxSSHHostKeyRotationDays {
			return fmt.Errorf("invalid rotation days: %s", args[0])
		}
		cfg, revision, err := loadCandidateConfig(ctx, api)
		if err != nil {
			return err
		}
		cfg.System.SSH.HostKeyRotationDays = days
		return api.saveJSON(ctx, "/api/v1/config/candidate", cfg, revision, out)
	}
}

func setSystemSSHShellModeAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("usage: set system ssh shell-mode <linux|appliance>")
		}
		mode := strings.ToLower(strings.TrimSpace(args[0]))
		if mode != "linux" && mode != "appliance" {
			return fmt.Errorf("invalid shell-mode %q (expected linux or appliance)", args[0])
		}
		cfg, revision, err := loadCandidateConfig(ctx, api)
		if err != nil {
			return err
		}
		cfg.System.SSH.ShellMode = mode
		return api.saveJSON(ctx, "/api/v1/config/candidate", cfg, revision, out)
	}
}

func parseBoolArg(s string) (bool, error) {
	v := strings.ToLower(strings.TrimSpace(s))
	switch v {
	case "1", "true", "yes", "on", "enable", "enabled":
		return true, nil
	case "0", "false", "no", "off", "disable", "disabled":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean value %q", s)
	}
}

func showIDSRulesAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var idsCfg config.IDSConfig
		if err := api.getJSON(ctx, "/api/v1/ids/rules", &idsCfg); err != nil {
			return err
		}
		if out == nil {
			return nil
		}
		fmt.Fprintf(out, "enabled: %s\n\n", yesNoStr(idsCfg.Enabled))
		if len(idsCfg.Rules) == 0 {
			fmt.Fprintln(out, "No IDS rules.")
			return nil
		}
		t := newTable("ID", "TITLE", "PROTO", "KIND", "SEV", "MESSAGE")
		for _, r := range idsCfg.Rules {
			t.addRow(
				r.ID,
				truncate(firstNonEmpty(r.Title, "—"), 30),
				firstNonEmpty(r.Proto, "*"),
				firstNonEmpty(r.Kind, "*"),
				firstNonEmpty(r.Severity, "—"),
				truncate(firstNonEmpty(r.Message, "—"), 40),
			)
		}
		t.render(out)
		return nil
	}
}

func loadCandidateConfig(ctx context.Context, api *API) (*config.Config, config.Revision, error) {
	var cfg config.Config
	revision, err := api.getConfigJSON(ctx, "/api/v1/config/candidate", &cfg)
	if err != nil {
		return nil, "", err
	}
	return &cfg, revision, nil
}

func boolDefault(v *bool, def bool) bool {
	if v == nil {
		return def
	}
	return *v
}

func sshPasswordSetting(v *bool) string {
	if v == nil {
		return "auto (bootstrap/lab)"
	}
	return yesNoStr(*v)
}
