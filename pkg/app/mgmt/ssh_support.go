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
	shellMode      string
	baseURL        string
}

func startSSH(ctx context.Context, logger *zap.SugaredLogger, cfg *config.Config, store config.Store, userStore users.Store, auditStore audit.Store, httpAddr string, loopbackAddr string, idx *ipInterfaceIndex, optionalFault func(error), ready ...func(*sshserver.Server)) (string, bool) {
	configureSSHPolicy(store, userStore)
	rt := resolveSSHRuntimeConfig(cfg, httpAddr, loopbackAddr)

	opts := sshserver.Options{
		ListenAddr:          rt.sshAddr,
		BaseURL:             rt.baseURL,
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
			live := resolveSSHRuntimeConfig(running, httpAddr, loopbackAddr)
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
	for _, notify := range ready {
		notify(srv)
	}

	if rt.bootstrapKey != "" {
		if err := srv.SeedAuthorizedKey(rt.bootstrapUser, rt.bootstrapKey); err != nil {
			logger.Errorf("ssh bootstrap key seed failed: %v", err)
		}
	}

	go func() {
		if err := srv.ListenAndServe(ctx); err != nil {
			logger.Errorf("ssh server exited: %v", err)
			if optionalFault != nil {
				optionalFault(fmt.Errorf("ssh %s: %w", rt.sshAddr, err))
			}
		}
	}()
	logger.Infof("ssh enabled on %s (admin only)", rt.sshAddr)
	return rt.sshAddr, true
}

func configureSSHPolicy(store config.Store, userStore users.Store) {
	if reporter, ok := store.(interface {
		SetSSHRuntimePolicyReader(func(context.Context) (config.SSHRuntimePolicy, error))
	}); ok {
		reporter.SetSSHRuntimePolicyReader(func(ctx context.Context) (config.SSHRuntimePolicy, error) {
			running, err := store.Load(ctx)
			if err != nil {
				return config.SSHRuntimePolicy{}, err
			}
			rt := resolveSSHRuntimeConfig(running, "", "")
			return config.SSHRuntimePolicy{
				AllowPassword:       rt.allowPassword,
				PasswordSource:      rt.passwordSource,
				AuthorizedKeysDir:   rt.authKeysDir,
				HostKeyRotationDays: rt.rotationDays,
			}, nil
		})
	}
	if validator, ok := store.(interface {
		SetSSHAccessValidator(func(context.Context, config.SSHConfig) error)
	}); ok {
		validator.SetSSHAccessValidator(func(ctx context.Context, ssh config.SSHConfig) error {
			candidate := &config.Config{}
			candidate.System.SSH = ssh
			rt := resolveSSHRuntimeConfig(candidate, "", "")
			return sshserver.ValidateAdminAuthorizedKey(ctx, userStore, rt.authKeysDir)
		})
	}
}

func resolveSSHRuntimeConfig(cfg *config.Config, httpAddr string, loopbackAddr string) sshRuntimeConfig {
	rt := sshRuntimeConfig{
		sshAddr:       common.EnvTrimmed("CONTAIND_SSH_ADDR", ""),
		authKeysDir:   common.Env("CONTAIND_SSH_AUTH_KEYS_DIR", ""),
		hostKeyPath:   common.Env("CONTAIND_SSH_HOST_KEY", ""),
		bootstrapKey:  common.EnvTrimmed("CONTAIND_SSH_BOOTSTRAP_ADMIN_KEY", ""),
		bootstrapUser: common.EnvTrimmed("CONTAIND_SSH_BOOTSTRAP_ADMIN_USER", ""),
	}
	if rt.sshAddr == "" && cfg != nil && cfg.System.SSH.ListenAddr != "" {
		rt.sshAddr = cfg.System.SSH.ListenAddr
	}
	if rt.sshAddr == "" {
		rt.sshAddr = ":2222"
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
	if cfg != nil {
		rt.banner = cfg.System.SSH.Banner
		rt.rotationDays = cfg.System.SSH.HostKeyRotationDays
		rt.shellMode = cfg.System.SSH.ShellMode
	}
	if env := common.EnvTrimmed("CONTAIND_SSH_SHELL_MODE", ""); env != "" {
		rt.shellMode = env
	}
	rt.allowPassword, rt.passwordSource = resolveSSHPasswordPolicy(cfg, rt.authKeysDir)
	rt.baseURL = resolveSSHBaseURL(httpAddr, loopbackAddr)
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

func resolveSSHBaseURL(httpAddr string, loopbackAddr string) string {
	if loopbackAddr != "" && loopbackAddr != httpAddr {
		return "http://" + loopbackAddr
	}
	if httpAddr != "" {
		_, port, err := net.SplitHostPort(httpAddr)
		if err == nil && port != "" {
			return "http://127.0.0.1:" + port
		}
	}
	return "http://127.0.0.1:8080"
}
