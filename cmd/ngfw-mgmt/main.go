package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	engineapi "github.com/containd/containd/api/engine"
	httpapi "github.com/containd/containd/api/http"
	"github.com/containd/containd/pkg/mp/sshserver"
	"github.com/containd/containd/pkg/cp/audit"
	"github.com/containd/containd/pkg/cp/services"
	"github.com/containd/containd/pkg/cli"
	"github.com/containd/containd/pkg/common/logging"
	"github.com/containd/containd/pkg/cp/config"
	"github.com/containd/containd/pkg/cp/users"
	"github.com/gin-gonic/gin"
)

type mgmtHealthResponse struct {
	Status     string `json:"status"`
	Component  string `json:"component"`
	Build      string `json:"build"`
	CommitHash string `json:"commitHash,omitempty"`
	Time       string `json:"time"`
}

func main() {
	logger := logging.New("[mgmt]")
	store := mustInitStore()
	defer store.Close()
	ensureDefaultConfig(logger, store)
	_ = cli.NewRegistry(store, nil) // placeholder until wired into SSH/HTTP transports
	auditStore := mustInitAuditStore()
	defer auditStore.Close()
	userStore := mustInitUsersStore()
	defer userStore.Close()
	_ = userStore.EnsureDefaultAdmin(context.Background())

	addr := addrFromEnv("NGFW_MGMT_ADDR", "")
	if addr == "" {
		if cfg, err := store.Load(context.Background()); err == nil {
			if cfg.System.Mgmt.ListenAddr != "" {
				addr = cfg.System.Mgmt.ListenAddr
			}
		}
		if addr == "" {
			addr = ":8080"
		}
	}

	var engineClient httpapi.EngineClient
	if engineURL := os.Getenv("NGFW_ENGINE_URL"); engineURL != "" {
		engineClient = engineapi.NewHTTPClient(engineURL)
	}
	serviceManager := services.NewManager(services.ManagerOptions{})
	router := httpapi.NewServerWithEngineAndServices(store, auditStore, engineClient, serviceManager, userStore)
	// Best-effort initial service render on startup.
	if cfg, err := store.Load(context.Background()); err == nil {
		_ = serviceManager.Apply(context.Background(), cfg.Services)
	}
	serveStaticUI(router)

	loopbackAddr := ensureLoopbackHTTPAddr(addr)

	// Start SSH server (admin-only) for interactive CLI.
	sshAddr, sshEnabled := startSSH(logger, store, userStore, auditStore, addr, loopbackAddr)

	printStartupHints(logger, addr, loopbackAddr, sshAddr, sshEnabled)

	logger.Printf("ngfw-mgmt listening on %s", addr)
	if loopbackAddr != "" && loopbackAddr != addr {
		logger.Printf("ngfw-mgmt also listening on %s (localhost)", loopbackAddr)
	}
	if err := serveHTTPDual(router, addr, loopbackAddr); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Fatalf("ngfw-mgmt server exited: %v", err)
	}
}

func addrFromEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func health(c *gin.Context) {
	c.JSON(http.StatusOK, mgmtHealthResponse{
		Status:    "ok",
		Component: "ngfw-mgmt",
		Build:     "dev",
		Time:      time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func serveStaticUI(router *gin.Engine) {
	uiDir := pickUIDir()
	if uiDir != "" {
		indexPath := filepath.Join(uiDir, "index.html")
		// Serve index at root.
		router.GET("/", func(c *gin.Context) {
			c.File(indexPath)
		})
		// For all other non-API paths, try to serve a static file or fall back to index.
		router.NoRoute(func(c *gin.Context) {
			reqPath := c.Request.URL.Path
			if reqPath == "/api" || strings.HasPrefix(reqPath, "/api/") {
				c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
				return
			}

			clean := filepath.Clean(reqPath)
			candidate := filepath.Join(uiDir, clean)
			if info, err := os.Stat(candidate); err == nil {
				if info.IsDir() {
					dirIndex := filepath.Join(candidate, "index.html")
					if _, err := os.Stat(dirIndex); err == nil {
						c.File(dirIndex)
						return
					}
				} else {
					c.File(candidate)
					return
				}
			}

			c.File(indexPath)
		})
		return
	}

	// Fallback simple response until the Next.js build pipeline lands.
	router.NoRoute(func(c *gin.Context) {
		c.String(http.StatusOK, "containd management API is running. UI build not found.")
	})
}

func pickUIDir() string {
	// Allow override for packaged builds.
	if override := os.Getenv("NGFW_UI_DIR"); override != "" {
		if dirExists(override) {
			return override
		}
	}

	// Prefer Next.js static export if present.
	candidates := []string{
		filepath.Join(".", "ui", "out"),
		filepath.Join(".", "ui", "public"),
		"/var/lib/ngfw/ui",
	}

	for _, c := range candidates {
		if dirExists(c) {
			return c
		}
	}
	return ""
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func ensureDefaultConfig(logger *log.Logger, store config.Store) {
	if store == nil {
		return
	}
	cfg, err := store.Load(context.Background())
	if err == nil && cfg != nil {
		return
	}
	if !errors.Is(err, config.ErrNotFound) {
		logger.Printf("failed to load config (continuing): %v", err)
		return
	}
	def := config.DefaultConfig()
	def.System.Hostname = "containd"
	def.System.Mgmt.ListenAddr = ":8080"
	if err := store.Save(context.Background(), def); err != nil {
		logger.Printf("failed to initialize default config: %v", err)
		return
	}
	logger.Printf("initialized default config")
}

func ensureLoopbackHTTPAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// If addr is malformed, don't attempt a loopback listener.
		return ""
	}
	h := strings.ToLower(strings.TrimSpace(host))
	switch h {
	case "", "0.0.0.0", "::", "[::]", "127.0.0.1", "localhost":
		return addr
	default:
		return net.JoinHostPort("127.0.0.1", port)
	}
}

func serveHTTPDual(handler http.Handler, addr string, loopbackAddr string) error {
	srv := &http.Server{Addr: addr, Handler: handler}
	if loopbackAddr == "" || loopbackAddr == addr {
		return srv.ListenAndServe()
	}
	loop := &http.Server{Addr: loopbackAddr, Handler: handler}
	errCh := make(chan error, 2)
	go func() { errCh <- loop.ListenAndServe() }()
	go func() { errCh <- srv.ListenAndServe() }()
	err := <-errCh
	_ = srv.Close()
	_ = loop.Close()
	return err
}

func startSSH(logger *log.Logger, store config.Store, userStore users.Store, auditStore audit.Store, httpAddr string, loopbackAddr string) (string, bool) {
	ctx := context.Background()
	sshAddr := addrFromEnv("NGFW_SSH_ADDR", "")
	authKeysDir := os.Getenv("NGFW_SSH_AUTH_KEYS_DIR")
	hostKeyPath := os.Getenv("NGFW_SSH_HOST_KEY")
	bootstrapKey := strings.TrimSpace(os.Getenv("NGFW_SSH_BOOTSTRAP_ADMIN_KEY"))
	bootstrapUser := strings.TrimSpace(os.Getenv("NGFW_SSH_BOOTSTRAP_ADMIN_USER"))
	allowPasswordEnv := strings.TrimSpace(os.Getenv("NGFW_SSH_ALLOW_PASSWORD"))

	cfg, _ := store.Load(ctx)
	if sshAddr == "" && cfg != nil && cfg.System.SSH.ListenAddr != "" {
		sshAddr = cfg.System.SSH.ListenAddr
	}
	if sshAddr == "" {
		sshAddr = ":2222"
	}
	if authKeysDir == "" && cfg != nil && cfg.System.SSH.AuthorizedKeysDir != "" {
		authKeysDir = cfg.System.SSH.AuthorizedKeysDir
	}
	if authKeysDir == "" {
		authKeysDir = "/data/ssh/authorized_keys.d"
	}
	if hostKeyPath == "" {
		hostKeyPath = "/data/ssh/host_key"
	}

	lab := os.Getenv("CONTAIND_LAB_MODE") == "1" || strings.EqualFold(os.Getenv("CONTAIND_LAB_MODE"), "true")
	allowPassword := lab
	if cfg != nil && cfg.System.SSH.AllowPassword {
		allowPassword = true
	}
	if allowPasswordEnv != "" {
		allowPassword = allowPasswordEnv == "1" || strings.EqualFold(allowPasswordEnv, "true") || strings.EqualFold(allowPasswordEnv, "yes")
	}

	baseURL := "http://127.0.0.1:8080"
	if loopbackAddr != "" && loopbackAddr != httpAddr {
		baseURL = "http://" + loopbackAddr
	} else if httpAddr != "" {
		// If mgmt listens on all interfaces, localhost should still work.
		_, port, err := net.SplitHostPort(httpAddr)
		if err == nil && port != "" {
			baseURL = "http://127.0.0.1:" + port
		}
	}

	opts := sshserver.Options{
		ListenAddr:        sshAddr,
		BaseURL:           baseURL,
		HostKeyPath:       hostKeyPath,
		AuthorizedKeysDir: authKeysDir,
		AllowPassword:     allowPassword,
		LabMode:           lab,
		JWTSecret:         []byte(strings.TrimSpace(os.Getenv("CONTAIND_JWT_SECRET"))),
		UserStore:         userStore,
		AuditStore:        auditStore,
	}
	srv, err := sshserver.New(opts)
	if err != nil {
		logger.Printf("ssh disabled: %v", err)
		return "", false
	}
	srv.EnsureAuthorizedKeysDir()

	// Optional one-time bootstrap: seed the admin's authorized key file from an env var.
	// This avoids a chicken/egg problem in production container deployments.
	if bootstrapKey != "" {
		if bootstrapUser == "" {
			bootstrapUser = "containd"
		}
		if err := srv.SeedAuthorizedKey(bootstrapUser, bootstrapKey); err != nil {
			logger.Printf("ssh bootstrap key seed failed: %v", err)
		}
	}

	go func() {
		if err := srv.ListenAndServe(context.Background()); err != nil {
			logger.Printf("ssh server exited: %v", err)
		}
	}()
	logger.Printf("ssh enabled on %s (admin only)", sshAddr)
	return sshAddr, true
}

func printStartupHints(logger *log.Logger, httpAddr string, loopbackAddr string, sshAddr string, sshEnabled bool) {
	mgmtPort := portOf(httpAddr)
	sshPort := portOf(sshAddr)

	logger.Println("------------------------------------------------------------")
	logger.Println("containd access")

	if mgmtPort != "" {
		logger.Printf("UI/API:  http://localhost:%s", mgmtPort)
	} else {
		logger.Printf("UI/API:  http://localhost (port from %q)", httpAddr)
	}

	if sshEnabled && sshPort != "" {
		logger.Printf("SSH CLI: ssh -p %s containd@localhost", sshPort)
		logger.Println("         then type: wizard")
	}

	ips := detectIPs()
	if len(ips) > 0 && mgmtPort != "" {
		logger.Printf("Container IPs: %s", strings.Join(ips, ", "))
		if bindsAll(httpAddr) {
			for _, ip := range ips {
				logger.Printf("UI/API via IP: http://%s:%s", ip, mgmtPort)
				if sshEnabled && sshPort != "" {
					logger.Printf("SSH via IP:    ssh -p %s containd@%s", sshPort, ip)
				}
			}
		} else if hostOnly(httpAddr) {
			logger.Printf("UI/API bind is restricted to %s; use localhost or reconfigure.", httpAddr)
		}
	}

	if os.Getenv("CONTAIND_LAB_MODE") == "1" || strings.EqualFold(os.Getenv("CONTAIND_LAB_MODE"), "true") {
		logger.Println("Lab defaults: username=containd password=containd")
	} else {
		logger.Println("Production note: provide SSH key or bootstrap key env var.")
		logger.Println("  - NGFW_SSH_BOOTSTRAP_ADMIN_KEY=\"ssh-ed25519 AAAA...\"")
	}
	logger.Println("Tip: docker compose logs -f containd")
	logger.Println("------------------------------------------------------------")
}

func portOf(addr string) string {
	if strings.TrimSpace(addr) == "" {
		return ""
	}
	host, port, err := net.SplitHostPort(addr)
	if err == nil {
		_ = host
		return port
	}
	// tolerate ":8080" without host (SplitHostPort already handles it),
	// but keep this fallback for odd values.
	if i := strings.LastIndex(addr, ":"); i != -1 && i+1 < len(addr) {
		return strings.TrimSpace(addr[i+1:])
	}
	return ""
}

func bindsAll(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	h := strings.ToLower(strings.TrimSpace(host))
	return h == "" || h == "0.0.0.0" || h == "::" || h == "[::]"
}

func hostOnly(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	h := strings.ToLower(strings.TrimSpace(host))
	return h == "127.0.0.1" || h == "localhost"
}

func detectIPs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ip := ipFromAddr(a)
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				if isRFC1918(ip4) {
					out = append(out, ip4.String())
				}
			}
		}
	}
	return out
}

func ipFromAddr(a net.Addr) net.IP {
	switch v := a.(type) {
	case *net.IPNet:
		return v.IP
	case *net.IPAddr:
		return v.IP
	default:
		_, ipnet, err := net.ParseCIDR(a.String())
		if err == nil && ipnet != nil {
			return ipnet.IP
		}
	}
	return nil
}

func isRFC1918(ip net.IP) bool {
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	switch {
	case ip4[0] == 10:
		return true
	case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
		return true
	case ip4[0] == 192 && ip4[1] == 168:
		return true
	default:
		return false
	}
}

func mustInitStore() config.Store {
	dbPath := addrFromEnv("NGFW_CONFIG_DB", filepath.Join("data", "config.db"))
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		logging.New("[mgmt]").Fatalf("failed to create config dir: %v", err)
	}
	store, err := config.NewSQLiteStore(dbPath)
	if err != nil {
		logging.New("[mgmt]").Fatalf("failed to open config store: %v", err)
	}
	return store
}

func mustInitAuditStore() audit.Store {
	dbPath := addrFromEnv("NGFW_AUDIT_DB", filepath.Join("data", "audit.db"))
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		logging.New("[mgmt]").Fatalf("failed to create audit dir: %v", err)
	}
	store, err := audit.NewSQLiteStore(dbPath)
	if err != nil {
		logging.New("[mgmt]").Fatalf("failed to open audit store: %v", err)
	}
	return store
}

func mustInitUsersStore() users.Store {
	dbPath := addrFromEnv("NGFW_USERS_DB", filepath.Join("data", "users.db"))
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		// If the requested path isn't writable (common in distroless/nonroot),
		// fall back to a local data dir that should be writable in dev images.
		fallback := filepath.Join("data", "users.db")
		if fallback != dbPath {
			_ = os.MkdirAll(filepath.Dir(fallback), 0o755)
			logging.New("[mgmt]").Printf("users db path %s not writable (%v); falling back to %s", dbPath, err, fallback)
			dbPath = fallback
		} else {
			logging.New("[mgmt]").Fatalf("failed to create users dir: %v", err)
		}
	}
	store, err := users.NewSQLiteStore(dbPath)
	if err != nil {
		logging.New("[mgmt]").Fatalf("failed to open users store: %v", err)
	}
	return store
}
