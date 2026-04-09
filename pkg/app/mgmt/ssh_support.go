// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package mgmtapp

import (
	"context"
	"net"
	"os"
	"strings"

	"go.uber.org/zap"

	"github.com/tonylturner/containd/pkg/common"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/users"
	"github.com/tonylturner/containd/pkg/mp/sshserver"
)

type sshRuntimeConfig struct {
	sshAddr       string
	authKeysDir   string
	hostKeyPath   string
	bootstrapKey  string
	bootstrapUser string
	allowPassword bool
	banner        string
	rotationDays  int
	shellMode     string
	baseURL       string
}

func startSSH(logger *zap.SugaredLogger, store config.Store, userStore users.Store, auditStore audit.Store, httpAddr string, loopbackAddr string, idx *ipInterfaceIndex) (string, bool) {
	cfg, _ := store.Load(context.Background())
	rt := resolveSSHRuntimeConfig(cfg, httpAddr, loopbackAddr)

	opts := sshserver.Options{
		ListenAddr:          rt.sshAddr,
		BaseURL:             rt.baseURL,
		HostKeyPath:         rt.hostKeyPath,
		AuthorizedKeysDir:   rt.authKeysDir,
		AllowPassword:       rt.allowPassword,
		Banner:              rt.banner,
		HostKeyRotationDays: rt.rotationDays,
		ShellMode:           rt.shellMode,
		LabMode:             isLabMode(),
		JWTSecret:           []byte(strings.TrimSpace(os.Getenv("CONTAIND_JWT_SECRET"))),
		UserStore:           userStore,
		AuditStore:          auditStore,
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
		return "", false
	}
	srv.EnsureAuthorizedKeysDir()

	if rt.bootstrapKey != "" {
		if err := srv.SeedAuthorizedKey(rt.bootstrapUser, rt.bootstrapKey); err != nil {
			logger.Errorf("ssh bootstrap key seed failed: %v", err)
		}
	}

	go func() {
		if err := srv.ListenAndServe(context.Background()); err != nil {
			logger.Errorf("ssh server exited: %v", err)
		}
	}()
	logger.Infof("ssh enabled on %s (admin only)", rt.sshAddr)
	return rt.sshAddr, true
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
	rt.allowPassword = resolveSSHAllowPassword(cfg, rt.authKeysDir)
	rt.baseURL = resolveSSHBaseURL(httpAddr, loopbackAddr)
	return rt
}

func resolveSSHAllowPassword(cfg *config.Config, authKeysDir string) bool {
	lab := isLabMode()
	allowPassword := lab
	if cfg != nil && cfg.System.SSH.AllowPassword {
		allowPassword = true
	}
	if !allowPassword && !lab && authKeysDirNeedsBootstrap(authKeysDir) {
		allowPassword = true
	}
	if env := common.EnvTrimmed("CONTAIND_SSH_ALLOW_PASSWORD", ""); env != "" {
		return env == "1" || strings.EqualFold(env, "true") || strings.EqualFold(env, "yes")
	}
	return allowPassword
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
