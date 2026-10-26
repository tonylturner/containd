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
	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/identity"
	"github.com/tonylturner/containd/pkg/cp/services"
	"github.com/tonylturner/containd/pkg/cp/users"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
	"go.uber.org/zap"
)

type Options struct {
	Reservation *mgmtpath.Reservation
	Combined    bool
}

type mgmtStores struct {
	store      config.Store
	auditStore audit.Store
	userStore  users.Store
	bootEvent  *dpevents.Event
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
	optionalFault       func(error)
	reservedHTTPAddr    string
}

func Run(ctx context.Context, opts Options) error {
	logger := logging.NewService("mgmt")
	logging.InstallSlogBridge(logger.Desugar())
	if err := validateJWTSecret(logger); err != nil {
		return err
	}

	if err := opts.Reservation.ValidateEngineBind(common.EnvTrimmed("CONTAIND_ENGINE_ADDR", ":8081")); err != nil {
		return err
	}
	if err := validateReservedEnvironment(opts.Reservation); err != nil {
		return err
	}
	if err := waitForReservedEngine(ctx, resolveEngineURL(logger, opts), opts.Reservation); err != nil {
		return err
	}
	stores, cfg, err := initMgmtStores(logger, opts.Reservation)
	if err != nil {
		return err
	}
	defer stores.store.Close()
	defer stores.auditStore.Close()
	defer stores.userStore.Close()

	runtimeCfg := reservationSafeBootListeners(cfg, opts.Reservation)
	if err := validateReservedBootEnvironment(runtimeCfg, opts.Reservation); err != nil {
		return err
	}
	listenerFaults := &bootListenerFaults{logger: logger}
	var optionalFault func(error)
	if opts.Reservation != nil {
		optionalFault = listenerFaults.record
	}
	listenerCfg, err := resolveMgmtListenerConfig(logger, runtimeCfg, optionalFault)
	if err != nil {
		return err
	}
	if opts.Reservation != nil {
		listenerCfg.reservedHTTPAddr = net.JoinHostPort(opts.Reservation.Local.Addr().String(), fmt.Sprint(opts.Reservation.Port))
	}

	var engineClient httpapi.EngineClient
	if engineURL := resolveEngineURL(logger, opts); engineURL != "" {
		engineClient = engineapi.NewHTTPClient(engineURL)
	}
	startDHCPLeaseAuditIngestor(ctx, logger, engineClient, stores.auditStore)
	serviceManager := &bootEventServices{Manager: services.NewManager(services.ManagerOptions{}), event: stores.bootEvent}
	identityResolver := identity.NewResolver()
	router := httpapi.NewServerWithEngineAndServices(stores.store, stores.auditStore, engineClient, serviceManager, stores.userStore, identityResolver, managementGuardHealth(resolveEngineURL(logger, opts)), httpapi.ManagementListenerFaults(listenerFaults.list))
	// Best-effort initial service render on startup.
	if cfg, err := stores.store.Load(ctx); err == nil && config.CheckManagementBootFault(ctx, stores.store) == nil {
		if applyErr := serviceManager.Apply(context.Background(), cfg.Services); applyErr != nil {
			logger.Warnf("failed to apply initial service config: %v", applyErr)
		}
	}
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
	serveStaticUI(router)
	stopEngineSync := startEngineSync(ctx, logger, stores.store, engineClient, serviceManager)
	defer stopEngineSync()

	// Enforce per-interface access toggles based on the destination IP.
	ipIndex := newIPInterfaceIndex()
	handler := mgmtAccessHandler(stores.store, ipIndex, opts.Reservation, router)

	// Start SSH server (admin-only) for interactive CLI.
	sshAddr, sshEnabled := startSSH(ctx, logger, runtimeCfg, stores.store, stores.userStore, stores.auditStore, listenerCfg.httpAddr, listenerCfg.httpLoopbackAddr, ipIndex, optionalFault)
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

func initMgmtStores(logger *zap.SugaredLogger, r *mgmtpath.Reservation) (mgmtStores, *config.Config, error) {
	store, err := initStore(r)
	if err != nil {
		return mgmtStores{}, nil, err
	}
	stores := mgmtStores{store: store}
	// Stored conflicts are recovery state, never a reason to remove management.
	fail := func(err error) (mgmtStores, *config.Config, error) { store.Close(); return mgmtStores{}, nil, err }
	if err := ensureDefaultConfig(logger, store); err != nil {
		return fail(err)
	}
	cfg, err := store.Load(context.Background())
	if err != nil {
		return fail(err)
	}

	// Repair stale interface.device bindings before the HTTP server begins
	// serving traffic. Without this, mgmtAccessHandler reads the stored
	// config with device fields pointing at kernel devices the OS may have
	// renumbered across container restarts — leading to false 403s on the
	// very first API call from the management plane.
	//
	// Blank the device fields on default-named logical interfaces first so
	// AutoBindDefaultInterfaceDevices reliably re-runs subnet-match
	// assignment. The "shouldRepair" gate inside autobind only triggers
	// when bindings are blank OR match the legacy eth0..ethN index pattern;
	// docker-shuffled bindings look neither, so without blanking, the
	// scrambled state survives. Subnet-based reassignment is the
	// authoritative determinism source (see CONTAIND_AUTO_*_SUBNET env vars
	// + assignBySubnet); we're not changing that, just making sure it runs.
	if cfg != nil {
		repaired, repairErr := config.Repair(context.Background(), stores.store, func(next *config.Config) error {
			// Keep the old bindings if discovery cannot produce a replacement.
			devices := make([]string, len(next.Interfaces))
			for i := range next.Interfaces {
				devices[i] = next.Interfaces[i].Device
			}
			blankDefaultInterfaceDevicesExcept(next, r)
			if !httpapi.AutoBindDefaultInterfaceDevicesReserved(next, r) {
				for i := range next.Interfaces {
					next.Interfaces[i].Device = devices[i]
				}
			}
			return nil
		})
		if repairErr != nil {
			logger.Warnf("boot interface repair: %v", repairErr)
		} else {
			cfg = repaired
		}
	}
	stores.auditStore = mustInitAuditStore()
	stores.userStore = mustInitUsersStore()
	if err := stores.userStore.EnsureDefaultAdmin(context.Background()); err != nil {
		stores.auditStore.Close()
		stores.userStore.Close()
		return fail(err)
	}
	event, err := recordReservationBootDecision(logger, stores, cfg, r)
	if err != nil {
		stores.auditStore.Close()
		stores.userStore.Close()
		return fail(err)
	}
	stores.bootEvent = event
	return stores, cfg, nil
}

// blankDefaultInterfaceDevices clears the Device field on each default
// logical interface (wan/dmz/lan1..lan6) so the subsequent
// AutoBindDefaultInterfaceDevices pass treats them as needing assignment.
// Non-default interfaces (custom user-named) are left untouched.
func blankDefaultInterfaceDevices(cfg *config.Config) { blankDefaultInterfaceDevicesExcept(cfg, nil) }

func blankDefaultInterfaceDevicesExcept(cfg *config.Config, r *mgmtpath.Reservation) {
	if cfg == nil {
		return
	}
	defaults := map[string]struct{}{}
	for _, name := range config.DefaultPhysicalInterfaces() {
		defaults[name] = struct{}{}
	}
	// A matching device name alone is not ownership after NIC renumbering:
	// an addressed default row may now point at the reserved NIC by accident.
	preserveReserved := r != nil && config.ValidateManagementInterfaces(cfg.Interfaces, r) == nil
	for i := range cfg.Interfaces {
		if preserveReserved && cfg.Interfaces[i].Device == r.Device {
			continue
		}
		if _, ok := defaults[cfg.Interfaces[i].Name]; ok {
			cfg.Interfaces[i].Device = ""
		}
	}
}

func resolveMgmtListenerConfig(logger *zap.SugaredLogger, cfg *config.Config, optionalFault func(error)) (mgmtListenerConfig, error) {
	listenerCfg := mgmtListenerConfig{
		httpAddr:      resolveHTTPAddr(cfg),
		httpsAddr:     resolveHTTPSAddr(cfg),
		enableHTTP:    boolDefault(cfgGetBool(cfg, func(c *config.Config) *bool { return c.System.Mgmt.EnableHTTP }), true),
		enableHTTPS:   boolDefault(cfgGetBool(cfg, func(c *config.Config) *bool { return c.System.Mgmt.EnableHTTPS }), true),
		optionalFault: optionalFault,
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
		if listenerCfg.optionalFault != nil {
			listenerCfg.optionalFault(fmt.Errorf("https TLS certificate: %w", err))
		}
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
		srv, lns, err := buildListenerServers(httpHandler, listenerCfg.httpAddr, listenerCfg.httpLoopbackAddr, nil, listenerCfg.reservedHTTPAddr, listenerCfg.optionalFault)
		if err != nil {
			return nil, nil, errChPrefix("http", err)
		}
		servers = append(servers, srv...)
		listeners = append(listeners, lns...)
	}
	if listenerCfg.enableHTTPS {
		srv, lns, err := buildListenerServers(handler, listenerCfg.httpsAddr, listenerCfg.httpsLoopbackAddr, newMgmtTLSConfig(listenerCfg.tlsCert, listenerCfg.tlsKey), "", listenerCfg.optionalFault)
		if err != nil {
			for _, listener := range listeners {
				_ = listener.Close()
			}
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
