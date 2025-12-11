package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/containd/containd/pkg/cp/config"
)

// NewServer builds a Gin engine with versioned routes for management APIs.
func NewServer(store config.Store) *gin.Engine {
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())

	api := r.Group("/api/v1")
	{
		api.GET("/health", healthHandler)
		api.GET("/config", getConfigHandler(store))
		api.POST("/config", saveConfigHandler(store))
		api.POST("/config/validate", validateConfigHandler())
		api.GET("/config/export", exportConfigHandler(store))
		api.POST("/config/import", importConfigHandler(store))
		api.GET("/zones", listZonesHandler(store))
		api.POST("/zones", createZoneHandler(store))
		api.DELETE("/zones/:name", deleteZoneHandler(store))
		api.GET("/interfaces", listInterfacesHandler(store))
		api.POST("/interfaces", createInterfaceHandler(store))
		api.DELETE("/interfaces/:name", deleteInterfaceHandler(store))
		api.GET("/firewall/rules", listFirewallRulesHandler(store))
		api.POST("/firewall/rules", createFirewallRuleHandler(store))
		api.DELETE("/firewall/rules/:id", deleteFirewallRuleHandler(store))
	}

	return r
}

func healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "ok",
		"component": "ngfw-mgmt",
		"build":     "dev",
		"time":      time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func getConfigHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := store.Load(c.Request.Context())
		if err != nil {
			if errors.Is(err, config.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "config not found"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, cfg)
	}
}

func saveConfigHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var cfg config.Config
		if err := c.ShouldBindJSON(&cfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON", "detail": err.Error()})
			return
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
		defer cancel()
		if err := store.Save(ctx, &cfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "saved"})
	}
}

func validateConfigHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		var cfg config.Config
		if err := c.ShouldBindJSON(&cfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON", "detail": err.Error()})
			return
		}
		if err := cfg.Validate(); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "valid"})
	}
}

func exportConfigHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := store.Load(c.Request.Context())
		if err != nil {
			if errors.Is(err, config.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "config not found"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, cfg)
	}
}

func importConfigHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
			return
		}
		var cfg config.Config
		if err := json.Unmarshal(body, &cfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON", "detail": err.Error()})
			return
		}
		if err := cfg.Validate(); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if err := store.Save(c.Request.Context(), &cfg); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "imported"})
	}
}

func listZonesHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, cfg.Zones)
	}
}

func createZoneHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var z config.Zone
		if err := c.ShouldBindJSON(&z); err != nil || z.Name == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid zone payload"})
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		for _, existing := range cfg.Zones {
			if existing.Name == z.Name {
				c.JSON(http.StatusBadRequest, gin.H{"error": "zone already exists"})
				return
			}
		}
		cfg.Zones = append(cfg.Zones, z)
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, z)
	}
}

func deleteZoneHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		name := c.Param("name")
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		for _, iface := range cfg.Interfaces {
			if iface.Zone == name {
				c.JSON(http.StatusBadRequest, gin.H{"error": "zone in use by interface"})
				return
			}
		}
		for _, rule := range cfg.Firewall.Rules {
			for _, z := range append(rule.SourceZones, rule.DestZones...) {
				if z == name {
					c.JSON(http.StatusBadRequest, gin.H{"error": "zone in use by firewall rule"})
					return
				}
			}
		}
		original := len(cfg.Zones)
		filtered := make([]config.Zone, 0, len(cfg.Zones))
		for _, z := range cfg.Zones {
			if z.Name != name {
				filtered = append(filtered, z)
			}
		}
		if len(filtered) == original {
			c.JSON(http.StatusNotFound, gin.H{"error": "zone not found"})
			return
		}
		cfg.Zones = filtered
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.Status(http.StatusNoContent)
	}
}

func listInterfacesHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, cfg.Interfaces)
	}
}

func createInterfaceHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var iface config.Interface
		if err := c.ShouldBindJSON(&iface); err != nil || iface.Name == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid interface payload"})
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		for _, existing := range cfg.Interfaces {
			if existing.Name == iface.Name {
				c.JSON(http.StatusBadRequest, gin.H{"error": "interface already exists"})
				return
			}
		}
		cfg.Interfaces = append(cfg.Interfaces, iface)
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, iface)
	}
}

func deleteInterfaceHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		name := c.Param("name")
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		original := len(cfg.Interfaces)
		filtered := make([]config.Interface, 0, len(cfg.Interfaces))
		for _, i := range cfg.Interfaces {
			if i.Name != name {
				filtered = append(filtered, i)
			}
		}
		if len(filtered) == original {
			c.JSON(http.StatusNotFound, gin.H{"error": "interface not found"})
			return
		}
		cfg.Interfaces = filtered
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.Status(http.StatusNoContent)
	}
}

func listFirewallRulesHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, cfg.Firewall.Rules)
	}
}

func createFirewallRuleHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var r config.Rule
		if err := c.ShouldBindJSON(&r); err != nil || r.ID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid rule payload"})
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		for _, existing := range cfg.Firewall.Rules {
			if existing.ID == r.ID {
				c.JSON(http.StatusBadRequest, gin.H{"error": "rule already exists"})
				return
			}
		}
		if cfg.Firewall.DefaultAction == "" {
			cfg.Firewall.DefaultAction = config.ActionAllow
		}
		cfg.Firewall.Rules = append(cfg.Firewall.Rules, r)
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, r)
	}
}

func deleteFirewallRuleHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		original := len(cfg.Firewall.Rules)
		filtered := make([]config.Rule, 0, len(cfg.Firewall.Rules))
		for _, r := range cfg.Firewall.Rules {
			if r.ID != id {
				filtered = append(filtered, r)
			}
		}
		if len(filtered) == original {
			c.JSON(http.StatusNotFound, gin.H{"error": "rule not found"})
			return
		}
		cfg.Firewall.Rules = filtered
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.Status(http.StatusNoContent)
	}
}

func loadOrInitConfig(ctx context.Context, store config.Store) (*config.Config, error) {
	cfg, err := store.Load(ctx)
	if err != nil {
		if errors.Is(err, config.ErrNotFound) {
			return &config.Config{
				Firewall: config.FirewallConfig{DefaultAction: config.ActionAllow},
			}, nil
		}
		return nil, err
	}
	if cfg.Firewall.DefaultAction == "" {
		cfg.Firewall.DefaultAction = config.ActionAllow
	}
	return cfg, nil
}
