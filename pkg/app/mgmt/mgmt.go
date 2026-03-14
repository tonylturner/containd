// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package mgmtapp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	engineapi "github.com/tonylturner/containd/api/engine"
	httpapi "github.com/tonylturner/containd/api/http"
	"github.com/tonylturner/containd/pkg/common"
	"github.com/tonylturner/containd/pkg/common/logging"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/identity"
	"github.com/tonylturner/containd/pkg/cp/services"
	"github.com/tonylturner/containd/pkg/cp/users"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
	"go.uber.org/zap"
)

type Options struct {
	Combined bool
}

type mgmtStores struct {
	store      config.Store
	auditStore audit.Store
	userStore  users.Store
}

type mgmtListenerConfig struct {
	httpAddr            string
	httpsAddr           string
	httpLoopbackAddr    string
	httpsLoopbackAddr   string
	enableHTTP          bool
	enableHTTPS         bool
	redirectHTTPToHTTPS bool
	enableHSTS          bool
	hstsMaxAge          int
	allowedOrigins      []string
	tlsCert             string
	tlsKey              string
}

func Run(ctx context.Context, opts Options) error {
	logger := logging.NewService("mgmt")
	logging.InstallSlogBridge(logger.Desugar())
	if err := validateJWTSecret(logger); err != nil {
		return err
	}

	stores, cfg, err := initMgmtStores(logger)
	if err != nil {
		return err
	}
	defer stores.store.Close()
	defer stores.auditStore.Close()
	defer stores.userStore.Close()

	listenerCfg, err := resolveMgmtListenerConfig(logger, cfg)
	if err != nil {
		return err
	}

	var engineClient httpapi.EngineClient
	if engineURL := resolveEngineURL(logger, opts); engineURL != "" {
		engineClient = engineapi.NewHTTPClient(engineURL)
	}
	startDHCPLeaseAuditIngestor(ctx, logger, engineClient, stores.auditStore)
	serviceManager := services.NewManager(services.ManagerOptions{})
	identityResolver := identity.NewResolver()
	router := httpapi.NewServerWithEngineAndServices(stores.store, stores.auditStore, engineClient, serviceManager, stores.userStore, identityResolver)
	// Best-effort initial service render on startup.
	if cfg, err := stores.store.Load(context.Background()); err == nil {
		if applyErr := serviceManager.Apply(context.Background(), cfg.Services); applyErr != nil {
			logger.Warnf("failed to apply initial service config: %v", applyErr)
		}
	}
	if serviceManager != nil {
		serviceManager.SetEventLister(func(limit int) []dpevents.Event {
			var out []dpevents.Event
			type eventLister interface {
				ListEvents(ctx context.Context, limit int) ([]dpevents.Event, error)
			}
			if ec, ok := engineClient.(eventLister); ok && ec != nil {
				if evs, err := ec.ListEvents(context.Background(), limit); err == nil {
					out = append(out, evs...)
				}
			}
			out = append(out, serviceManager.ListTelemetryEvents(limit)...)
			return out
		})
		serviceManager.StartAVWorker(context.Background())
	}
	serveStaticUI(router)

	// Enforce per-interface access toggles based on the destination IP.
	ipIndex := newIPInterfaceIndex()
	handler := mgmtAccessHandler(stores.store, ipIndex, router)

	// Start SSH server (admin-only) for interactive CLI.
	sshAddr, sshEnabled := startSSH(logger, stores.store, stores.userStore, stores.auditStore, listenerCfg.httpAddr, listenerCfg.httpLoopbackAddr, ipIndex)
	handler = applyMgmtHTTPMiddleware(logger, handler, listenerCfg)
	printStartupHints(logger, listenerCfg.httpAddr, listenerCfg.httpLoopbackAddr, listenerCfg.httpsAddr, listenerCfg.httpsLoopbackAddr, listenerCfg.enableHTTP, listenerCfg.enableHTTPS, sshAddr, sshEnabled)

	servers, listeners, err := buildMgmtServers(handler, listenerCfg)
	if err != nil {
		return err
	}
	return serveMgmtServers(ctx, servers, listeners)
}

func validateJWTSecret(logger *zap.SugaredLogger) error {
	jwtSecret := strings.TrimSpace(os.Getenv("CONTAIND_JWT_SECRET"))
	labMode := isLabMode()
	switch {
	case jwtSecret == "containd-dev-secret-change-me":
		if !labMode {
			return fmt.Errorf("CONTAIND_JWT_SECRET is set to the default example value; set a unique secret (e.g. openssl rand -hex 32) or enable CONTAIND_LAB_MODE=1 for development")
		}
		logger.Warn("WARNING: CONTAIND_JWT_SECRET is default (lab mode active)")
	case jwtSecret == "":
		if !labMode {
			return fmt.Errorf("CONTAIND_JWT_SECRET is empty; set a unique secret or enable CONTAIND_LAB_MODE=1 for development")
		}
		logger.Warn("WARNING: CONTAIND_JWT_SECRET is empty (lab mode active)")
	}
	return nil
}

func initMgmtStores(logger *zap.SugaredLogger) (mgmtStores, *config.Config, error) {
	stores := mgmtStores{
		store:      mustInitStore(),
		auditStore: mustInitAuditStore(),
		userStore:  mustInitUsersStore(),
	}
	ensureDefaultConfig(logger, stores.store)
	_ = stores.userStore.EnsureDefaultAdmin(context.Background())

	cfg, err := stores.store.Load(context.Background())
	if err != nil && !errors.Is(err, config.ErrNotFound) {
		logger.Warnf("failed to load config on startup: %v", err)
	}
	return stores, cfg, nil
}

func resolveMgmtListenerConfig(logger *zap.SugaredLogger, cfg *config.Config) (mgmtListenerConfig, error) {
	listenerCfg := mgmtListenerConfig{
		httpAddr:    resolveHTTPAddr(cfg),
		httpsAddr:   resolveHTTPSAddr(cfg),
		enableHTTP:  boolDefault(cfgGetBool(cfg, func(c *config.Config) *bool { return c.System.Mgmt.EnableHTTP }), true),
		enableHTTPS: boolDefault(cfgGetBool(cfg, func(c *config.Config) *bool { return c.System.Mgmt.EnableHTTPS }), true),
	}
	listenerCfg.httpLoopbackAddr = ensureLoopbackHTTPAddr(listenerCfg.httpAddr)
	listenerCfg.httpsLoopbackAddr = ensureLoopbackHTTPAddr(listenerCfg.httpsAddr)
	listenerCfg.redirectHTTPToHTTPS = boolDefault(cfgGetBool(cfg, func(c *config.Config) *bool { return c.System.Mgmt.RedirectHTTPToHTTPS }), false)
	listenerCfg.enableHSTS = boolDefault(cfgGetBool(cfg, func(c *config.Config) *bool { return c.System.Mgmt.EnableHSTS }), true)
	listenerCfg.hstsMaxAge = cfgGetInt(cfg, func(c *config.Config) int { return c.System.Mgmt.HSTSMaxAgeSeconds }, 31536000)
	if listenerCfg.hstsMaxAge <= 0 {
		listenerCfg.hstsMaxAge = 31536000
	}
	listenerCfg.allowedOrigins = getAllowedOrigins()
	listenerCfg.tlsCert, listenerCfg.tlsKey = resolveTLSFiles(cfg)
	if !listenerCfg.enableHTTPS {
		return listenerCfg, nil
	}
	tlsCert, tlsKey, err := ensureSelfSignedTLSFiles(listenerCfg.tlsCert, listenerCfg.tlsKey, detectIPs())
	if err != nil {
		logger.Warnf("https disabled: failed to ensure TLS cert: %v", err)
		listenerCfg.enableHTTPS = false
		return listenerCfg, nil
	}
	listenerCfg.tlsCert = tlsCert
	listenerCfg.tlsKey = tlsKey
	return listenerCfg, nil
}

func resolveHTTPAddr(cfg *config.Config) string {
	httpAddr := common.EnvTrimmed("CONTAIND_MGMT_ADDR", "")
	if httpAddr == "" && cfg != nil {
		httpAddr = common.FirstNonEmpty(cfg.System.Mgmt.HTTPListenAddr, cfg.System.Mgmt.ListenAddr)
	}
	if httpAddr == "" {
		return ":8080"
	}
	return httpAddr
}

func resolveHTTPSAddr(cfg *config.Config) string {
	if httpsAddr := common.EnvTrimmed("CONTAIND_MGMT_HTTPS_ADDR", ""); httpsAddr != "" {
		return httpsAddr
	}
	if cfg != nil && cfg.System.Mgmt.HTTPSListenAddr != "" {
		return cfg.System.Mgmt.HTTPSListenAddr
	}
	return ":8443"
}

func applyMgmtHTTPMiddleware(logger *zap.SugaredLogger, handler http.Handler, listenerCfg mgmtListenerConfig) http.Handler {
	handler = hstsHandler(listenerCfg.enableHSTS, listenerCfg.hstsMaxAge, handler)
	if len(listenerCfg.allowedOrigins) == 0 {
		return handler
	}
	logger.Infof("CORS/frame-embedding enabled for origins: %v", listenerCfg.allowedOrigins)
	handler = corsHandler(handler, listenerCfg.allowedOrigins)
	return frameOptionsHandler(handler, listenerCfg.allowedOrigins)
}

func buildMgmtServers(handler http.Handler, listenerCfg mgmtListenerConfig) ([]*http.Server, []net.Listener, error) {
	errChPrefix := func(proto string, err error) error {
		return fmt.Errorf("%s disabled: %w", proto, err)
	}
	var servers []*http.Server
	var listeners []net.Listener
	if listenerCfg.enableHTTP {
		httpHandler := handler
		if listenerCfg.redirectHTTPToHTTPS {
			httpHandler = redirectToHTTPSHandler(listenerCfg.httpsAddr, httpHandler)
		}
		srv, lns, err := buildHTTPServers(httpHandler, listenerCfg.httpAddr, listenerCfg.httpLoopbackAddr)
		if err != nil {
			return nil, nil, errChPrefix("http", err)
		}
		servers = append(servers, srv...)
		listeners = append(listeners, lns...)
	}
	if listenerCfg.enableHTTPS {
		srv, lns, err := buildHTTPSServers(handler, listenerCfg.httpsAddr, listenerCfg.httpsLoopbackAddr, newMgmtTLSConfig(listenerCfg.tlsCert, listenerCfg.tlsKey))
		if err != nil {
			return nil, nil, errChPrefix("https", err)
		}
		servers = append(servers, srv...)
		listeners = append(listeners, lns...)
	}
	if len(servers) == 0 {
		return nil, nil, fmt.Errorf("no management listeners enabled")
	}
	return servers, listeners, nil
}

func newMgmtTLSConfig(tlsCert, tlsKey string) *tls.Config {
	reloader := newCertReloader(tlsCert, tlsKey)
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		GetCertificate: reloader.GetCertificate,
	}
}

func serveMgmtServers(ctx context.Context, servers []*http.Server, listeners []net.Listener) error {
	errCh := make(chan error, len(servers))
	for i := range servers {
		go serveMgmtServer(servers[i], listeners[i], errCh)
	}

	select {
	case <-ctx.Done():
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer shutdownCancel()
		for _, s := range servers {
			_ = s.Shutdown(shutdownCtx)
		}
		return ctx.Err()
	case err := <-errCh:
		for _, s := range servers {
			_ = s.Close()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("containd mgmt server exited: %w", err)
		}
		return nil
	}
}

func serveMgmtServer(server *http.Server, listener net.Listener, errCh chan<- error) {
	if server.TLSConfig != nil {
		errCh <- server.Serve(tls.NewListener(listener, server.TLSConfig))
		return
	}
	errCh <- server.Serve(listener)
}

func isLabMode() bool {
	return os.Getenv("CONTAIND_LAB_MODE") == "1" || strings.EqualFold(os.Getenv("CONTAIND_LAB_MODE"), "true")
}
