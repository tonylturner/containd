// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package mgmtapp

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"go.uber.org/zap"

	httpapi "github.com/tonylturner/containd/api/http"
	"github.com/tonylturner/containd/pkg/common"
	"github.com/tonylturner/containd/pkg/common/labmode"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/users"
	"github.com/tonylturner/containd/pkg/mp/sshserver"
)

type sshRuntimeConfig struct {
	sshAddr        string
	authKeysDir    string
	hostKeyPath    string
	bootstrapKey   string
	bootstrapUser  string
	allowPassword  bool
	passwordSource string
	banner         string
	rotationDays   int
	// shellMode is set at startup; SSH does not reread it.
	shellMode       string
	shellModeSource string
}

// startSSH binds the SSH socket and serves it best effort: SSH CLI sessions
// call the management listeners this process has bound (see
// httpapi.LoopbackManagementAPI). It records SSH as bound management only
// once its socket bound, and returns that socket's address. SSH stays off
// with a fault when CLI sessions have no listener to call or the socket does
// not bind; neither stops HTTP or HTTPS.
func startSSH(ctx context.Context, logger *zap.SugaredLogger, cfg *config.Config, store config.Store, userStore users.Store, auditStore audit.Store, idx *ipInterfaceIndex, optionalFault func(error), ready ...func(*sshserver.Server)) (string, bool) {
	rt := resolveSSHRuntimeConfig(cfg)
	configureSSHPolicy(store, userStore, rt)
	baseURL, apiClient, err := httpapi.LoopbackManagementAPI()
	if err != nil {
		err = fmt.Errorf("ssh disabled: CLI sessions have no management API to call: %w", err)
		logger.Warn(err)
		if optionalFault != nil {
			optionalFault(err)
		}
		return "", false
	}

	opts := sshserver.Options{
		ListenAddr:          rt.sshAddr,
		BaseURL:             baseURL,
		APIClient:           apiClient,
		HostKeyPath:         rt.hostKeyPath,
		AuthorizedKeysDir:   rt.authKeysDir,
		AllowPassword:       rt.allowPassword,
		Banner:              rt.banner,
		HostKeyRotationDays: rt.rotationDays,
		HostKeyRotationDaysFunc: func(ctx context.Context) (int, error) {
			if store == nil {
				return rt.rotationDays, nil
			}
			running, err := store.Load(ctx)
			if err != nil {
				return 0, err
			}
			return running.System.SSH.HostKeyRotationDays, nil
		},
		AuthPolicy: func(ctx context.Context) (bool, string, error) {
			if store == nil {
				return rt.allowPassword, rt.authKeysDir, nil
			}
			running, err := store.Load(ctx)
			if err != nil {
				return false, "", err
			}
			live := resolveSSHRuntimeConfig(running)
			return live.allowPassword, live.authKeysDir, nil
		},
		ShellMode:  rt.shellMode,
		LabMode:    labmode.Enabled(),
		JWTSecret:  []byte(strings.TrimSpace(os.Getenv("CONTAIND_JWT_SECRET"))),
		UserStore:  userStore,
		AuditStore: auditStore,
		AllowLocalIP: func(ip net.IP) bool {
			if ip == nil || ip.IsLoopback() {
				return true
			}
			cfg, _ := store.Load(context.Background())
			ifaceName := ""
			if idx != nil {
				ifaceName = idx.lookup(ip)
			}
			return sshAllowedOnInterface(cfg, ifaceName)
		},
	}
	srv, err := sshserver.New(opts)
	if err != nil {
		logger.Warnf("ssh disabled: %v", err)
		if optionalFault != nil {
			optionalFault(fmt.Errorf("ssh disabled: %w", err))
		}
		return "", false
	}
	srv.EnsureAuthorizedKeysDir()
	if rt.bootstrapKey != "" {
		if err := srv.SeedAuthorizedKey(rt.bootstrapUser, rt.bootstrapKey); err != nil {
			logger.Errorf("ssh bootstrap key seed failed: %v", err)
		}
	}

	if err := srv.Listen(ctx); err != nil {
		err = fmt.Errorf("ssh disabled: %s: %w", rt.sshAddr, err)
		logger.Warn(err)
		if optionalFault != nil {
			optionalFault(err)
		}
		return "", false
	}
	for _, notify := range ready {
		notify(srv)
	}
	addr := srv.Addr().String()
	publishBoundSSH(addr)
	go func() {
		if err := srv.Serve(ctx); err != nil {
			logger.Errorf("ssh server exited: %v", err)
		}
	}()
	logger.Infof("ssh enabled on %s (admin only)", addr)
	return addr, true
}

// configureSSHPolicy registers the effective SSH policy reader. Password
// and key settings are read live; the shell mode is the one started.
func configureSSHPolicy(store config.Store, userStore users.Store, started sshRuntimeConfig) {
	if reporter, ok := store.(interface {
		SetSSHRuntimePolicyReader(func(context.Context) (config.SSHRuntimePolicy, error))
	}); ok {
		reporter.SetSSHRuntimePolicyReader(func(ctx context.Context) (config.SSHRuntimePolicy, error) {
			running, err := store.Load(ctx)
			if err != nil {
				return config.SSHRuntimePolicy{}, err
			}
			rt := resolveSSHRuntimeConfig(running)
			return config.SSHRuntimePolicy{
				AllowPassword:       rt.allowPassword,
				PasswordSource:      rt.passwordSource,
				AuthorizedKeysDir:   rt.authKeysDir,
				HostKeyRotationDays: rt.rotationDays,
				ShellMode:           started.shellMode,
				ShellModeSource:     started.shellModeSource,
			}, nil
		})
	}
	if validator, ok := store.(interface {
		SetSSHAccessValidator(func(context.Context, config.SSHConfig) error)
	}); ok {
		validator.SetSSHAccessValidator(func(ctx context.Context, ssh config.SSHConfig) error {
			candidate := &config.Config{}
			candidate.System.SSH = ssh
			rt := resolveSSHRuntimeConfig(candidate)
			return sshserver.ValidateAdminAuthorizedKey(ctx, userStore, rt.authKeysDir)
		})
	}
}

func resolveSSHRuntimeConfig(cfg *config.Config) sshRuntimeConfig {
	rt := sshRuntimeConfig{
		sshAddr:       config.EffectiveManagementListeners(cfg).SSH.Addr,
		authKeysDir:   common.Env("CONTAIND_SSH_AUTH_KEYS_DIR", ""),
		hostKeyPath:   common.Env("CONTAIND_SSH_HOST_KEY", ""),
		bootstrapKey:  common.EnvTrimmed("CONTAIND_SSH_BOOTSTRAP_ADMIN_KEY", ""),
		bootstrapUser: common.EnvTrimmed("CONTAIND_SSH_BOOTSTRAP_ADMIN_USER", ""),
	}
	if rt.authKeysDir == "" && cfg != nil && cfg.System.SSH.AuthorizedKeysDir != "" {
		rt.authKeysDir = cfg.System.SSH.AuthorizedKeysDir
	}
	if rt.authKeysDir == "" {
		rt.authKeysDir = "/data/ssh/authorized_keys.d"
	}
	if rt.hostKeyPath == "" {
		rt.hostKeyPath = "/data/ssh/host_key"
	}
	if rt.bootstrapUser == "" {
		rt.bootstrapUser = "containd"
	}
	savedShellMode := ""
	if cfg != nil {
		rt.banner = cfg.System.SSH.Banner
		rt.rotationDays = cfg.System.SSH.HostKeyRotationDays
		savedShellMode = cfg.System.SSH.ShellMode
	}
	rt.shellMode, rt.shellModeSource = config.ResolveSSHShellMode(savedShellMode, os.Getenv(config.EnvSSHShellMode))
	rt.allowPassword, rt.passwordSource = resolveSSHPasswordPolicy(cfg, rt.authKeysDir)
	return rt
}

func resolveSSHPasswordPolicy(cfg *config.Config, authKeysDir string) (bool, string) {
	// A persisted disable is authoritative, including over environment/lab defaults.
	if cfg != nil && cfg.System.SSH.AllowPassword != nil && !*cfg.System.SSH.AllowPassword {
		return false, "config"
	}
	if env := common.EnvTrimmed("CONTAIND_SSH_ALLOW_PASSWORD", ""); env != "" {
		return env == "1" || strings.EqualFold(env, "true") || strings.EqualFold(env, "yes"), "environment (CONTAIND_SSH_ALLOW_PASSWORD)"
	}
	if cfg != nil && cfg.System.SSH.AllowPassword != nil {
		return *cfg.System.SSH.AllowPassword, "config"
	}
	if labmode.Enabled() {
		return true, "lab default"
	}
	return authKeysDirNeedsBootstrap(authKeysDir), "bootstrap default"
}

func authKeysDirNeedsBootstrap(authKeysDir string) bool {
	entries, err := os.ReadDir(authKeysDir)
	if err != nil {
		return true
	}
	return len(entries) == 0
}
