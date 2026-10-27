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
	"sync/atomic"
	"time"

	engineapi "github.com/tonylturner/containd/api/engine"
	httpapi "github.com/tonylturner/containd/api/http"
	engineapp "github.com/tonylturner/containd/pkg/app/engine"
	"github.com/tonylturner/containd/pkg/common/labmode"
	"github.com/tonylturner/containd/pkg/common/logging"
	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/services"
	"github.com/tonylturner/containd/pkg/cp/users"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/mp/sshserver"
	"go.uber.org/zap"
)

type Options struct {
	Reservation *mgmtpath.Reservation
	Combined    bool
	Reload      <-chan struct{}
}

type mgmtStores struct {
	store       config.Store
	auditStore  audit.Store
	userStore   users.Store
	bootEvent   *dpevents.Event
	scopeEvents []dpevents.Event
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

	if err := opts.Reservation.ValidateEngineBind(engineapp.ListenAddr(opts.Combined)); err != nil {
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
	auditLog, ok := stores.auditStore.(audit.ForwardLog)
	if !ok {
		return fmt.Errorf("audit store %T cannot be forwarded to syslog", stores.auditStore)
	}
	serviceManager.SetAuditLog(auditLog)
	var sshServer atomic.Pointer[sshserver.Server]
	resetSessions := httpapi.FactoryResetSessions(func(_ context.Context, initiator string) {
		if srv := sshServer.Load(); srv != nil {
			srv.RevokeConnections(initiator)
		}
	})
	router := httpapi.NewServerWithEngineAndServices(stores.store, stores.auditStore, engineClient, serviceManager, stores.userStore, managementGuardHealth(resolveEngineURL(logger, opts)), httpapi.ManagementListenerFaults(listenerFaults.list), resetSessions)
	serveStaticUI(router)
	// Enforce per-interface access toggles based on the destination IP.
	ipIndex := newIPInterfaceIndex()
	access := mgmtAccessHandler(stores.store, ipIndex, opts.Reservation, router)
	// Bind before any runtime apply: a listener fallback enters recovery.
	bound, err := bindManagement(logger, stores, runtimeCfg, opts.Reservation, listenerCfg, func(lc mgmtListenerConfig) (mgmtBinds, error) {
		return buildMgmtServers(applyMgmtHTTPMiddleware(logger, access, lc), lc)
	})
	if err != nil {
		return err
	}
	if bound.event != nil {
		serviceManager.event = bound.event
	}
	runtimeCfg, listenerCfg = bound.cfg, bound.listener
	publishBoundManagement(listenerCfg, bound.binds)
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
		migrationCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		migrations, err := publishScopeMigrations(migrationCtx, stores)
		if err != nil {
			logger.Errorw("deliver industrial scope migration telemetry", "error", err)
		} else {
			out = append(out, migrations...)
		}
		return out
	})
	stopEngineSync := startEngineSync(ctx, logger, stores.store, engineClient, serviceManager)
	defer stopEngineSync()
	stopReload := startConfigReload(ctx, logger, stores.store, stores.auditStore, engineClient, serviceManager, opts.Reload)
	defer stopReload()

	// Start SSH server (admin-only) for interactive CLI.
	sshAddr, sshEnabled := startSSH(ctx, logger, runtimeCfg, stores.store, stores.userStore, stores.auditStore, ipIndex, optionalFault, sshServer.Store)
	printStartupHints(logger, listenerCfg.httpAddr, listenerCfg.httpLoopbackAddr, listenerCfg.httpsAddr, listenerCfg.httpsLoopbackAddr, listenerCfg.enableHTTP, listenerCfg.enableHTTPS, sshAddr, sshEnabled)
	return serveMgmtServers(ctx, bound.binds.servers, bound.binds.listeners)
}

func validateJWTSecret(logger *zap.SugaredLogger) error {
	jwtSecret := strings.TrimSpace(os.Getenv("CONTAIND_JWT_SECRET"))
	labMode := labmode.Enabled()
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
	event, err := recordBootDecision(logger, stores, cfg, r)
	if err != nil {
		stores.auditStore.Close()
		stores.userStore.Close()
		return fail(err)
	}
	stores.scopeEvents, err = publishScopeMigrations(context.Background(), stores)
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
			// Structural validity alone cannot establish ownership: on a
			// partial appliance an unaddressed ordinary row may now carry the
			// reserved NIC's old ethN name. Explicit subnet authority wins.
			subnet := httpapi.DefaultInterfaceSubnetOverride(cfg.Interfaces[i].Name)
			_, network, err := net.ParseCIDR(subnet)
			if subnet == "" || err == nil && network.Contains(net.IP(r.Local.Addr().AsSlice())) {
				continue
			}
		}
		if _, ok := defaults[cfg.Interfaces[i].Name]; ok {
			cfg.Interfaces[i].Device = ""
		}
	}
}

func resolveMgmtListenerConfig(logger *zap.SugaredLogger, cfg *config.Config, optionalFault func(error)) (mgmtListenerConfig, error) {
	listeners := config.EffectiveManagementListeners(cfg)
	listenerCfg := mgmtListenerConfig{
		httpAddr:      listeners.HTTP.Addr,
		httpsAddr:     listeners.HTTPS.Addr,
		enableHTTP:    listeners.HTTP.Enabled,
		enableHTTPS:   listeners.HTTPS.Enabled,
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

// publishBoundManagement records the sockets b holds as this process's
// bound management: every compile in this process admits them until the
// next start, and the console and SSH CLI sessions call them on loopback
// (see httpapi.LoopbackManagementAPI). SSH is not bound yet: startSSH adds
// it once its socket binds (publishBoundSSH).
func publishBoundManagement(lc mgmtListenerConfig, b mgmtBinds) {
	httpapi.SetServedManagement(lc.servedManagement(b))
	config.SetBoundManagementListeners(b.record())
}

// publishBoundSSH adds the SSH socket bound at addr to the bound management
// that publishBoundManagement recorded. Both run once, in order, at startup.
func publishBoundSSH(addr string) {
	bound := config.BoundManagementListeners()
	bound.SSH = config.ManagementListener{Addr: addr, Enabled: true}
	config.SetBoundManagementListeners(bound)
}

// record is the HTTP and HTTPS listeners b holds, each at the address its
// own socket bound, else at its loopback socket, and off when neither bound.
func (b mgmtBinds) record() config.ManagementListeners {
	return config.ManagementListeners{HTTP: b.http.record(), HTTPS: b.https.record()}
}

// servedManagement is what the listeners b holds serve beyond their
// addresses. The certificate and key are the resolved, possibly generated,
// files of the HTTPS listener, which a listener fallback or an environment
// override can make differ from the saved settings; empty when no HTTPS
// socket is bound.
func (lc mgmtListenerConfig) servedManagement(b mgmtBinds) httpapi.ServedManagement {
	served := httpapi.ServedManagement{
		HTTPRedirects: b.redirects,
		HTTPLoopback:  b.http.loopback != "",
		HTTPSLoopback: b.https.loopback != "",
	}
	if b.https.record().Enabled {
		served.CertFile, served.KeyFile = lc.tlsCert, lc.tlsKey
	}
	return served
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

// buildMgmtServers binds the listeners of listenerCfg. HTTPS binds first:
// the HTTP listener redirects to HTTPS only when configured to and HTTPS
// bound its own socket.
func buildMgmtServers(handler http.Handler, listenerCfg mgmtListenerConfig) (mgmtBinds, error) {
	var b mgmtBinds
	fail := func(proto string, err error) (mgmtBinds, error) {
		b.close()
		return mgmtBinds{}, fmt.Errorf("%s disabled: %w", proto, err)
	}
	if listenerCfg.enableHTTPS {
		bound, err := b.bindListener(handler, listenerCfg.httpsAddr, listenerCfg.httpsLoopbackAddr, newMgmtTLSConfig(listenerCfg.tlsCert, listenerCfg.tlsKey), "", listenerCfg.optionalFault)
		if err != nil {
			return fail("https", err)
		}
		b.https = bound
	}
	if listenerCfg.enableHTTP {
		httpHandler := handler
		if listenerCfg.redirectHTTPToHTTPS && b.https.addr != "" {
			httpHandler = redirectToHTTPSHandler(listenerCfg.httpsAddr, httpHandler)
			b.redirects = true
		}
		bound, err := b.bindListener(httpHandler, listenerCfg.httpAddr, listenerCfg.httpLoopbackAddr, nil, listenerCfg.reservedHTTPAddr, listenerCfg.optionalFault)
		if err != nil {
			return fail("http", err)
		}
		b.http = bound
	}
	if len(b.servers) == 0 {
		return mgmtBinds{}, fmt.Errorf("no management listeners enabled")
	}
	return b, nil
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
