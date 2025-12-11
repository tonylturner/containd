package main

import (
	"net/http"
	"os"
	"path/filepath"
	"time"

	httpapi "github.com/containd/containd/api/http"
	"github.com/containd/containd/pkg/cli"
	"github.com/containd/containd/pkg/common/logging"
	"github.com/containd/containd/pkg/cp/config"
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
	addr := addrFromEnv("NGFW_MGMT_ADDR", ":8080")
	store := mustInitStore()
	defer store.Close()
	_ = cli.NewRegistry(store, nil) // placeholder until wired into SSH/HTTP transports

	router := httpapi.NewServer(store)
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
		router.Static("/", uiDir)
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
