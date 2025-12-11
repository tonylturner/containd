package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

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
	addr := addrFromEnv("NGFW_MGMT_ADDR", ":8080")
	router := gin.Default()

	router.GET("/api/v1/health", health)
	serveStaticUI(router)

	log.Printf("ngfw-mgmt listening on %s", addr)
	if err := router.Run(addr); err != nil && err != http.ErrServerClosed {
		log.Fatalf("ngfw-mgmt server exited: %v", err)
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
	uiDir := filepath.Join(".", "ui", "public")
	if _, err := os.Stat(uiDir); err == nil {
		router.Static("/", uiDir)
		return
	}

	// Fallback simple response until the Next.js build pipeline lands.
	router.NoRoute(func(c *gin.Context) {
		c.String(http.StatusOK, "containd management API is running. UI build not found.")
	})
}
