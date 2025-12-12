package main

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	engineapi "github.com/containd/containd/api/engine"
	httpapi "github.com/containd/containd/api/http"
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

	logger.Printf("ngfw-mgmt listening on %s", addr)
	if err := router.Run(addr); err != nil && err != http.ErrServerClosed {
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
