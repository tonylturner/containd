// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"context"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	cpservices "github.com/tonylturner/containd/pkg/cp/services"
)

func getVPNHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := store.LoadCandidate(c.Request.Context())
		if err != nil {
			internalError(c, err)
			return
		}
		redacted := cfg.Services.VPN.RedactedVPNCopy()
		c.JSON(http.StatusOK, redacted)
	}
}

func setVPNHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var vpnCfg config.VPNConfig
		if err := c.ShouldBindJSON(&vpnCfg); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		cfg, ok := stageCandidate(c, store, func(cfg *config.Config) bool {
			vpnCfg.RestoreRedactedSecrets(cfg.Services.VPN)
			cfg.Services.VPN = vpnCfg
			return true
		})
		if !ok {
			return
		}
		auditLog(c, audit.Record{Action: "services.vpn.set", Target: "candidate", Detail: "candidate"})
		c.JSON(http.StatusOK, cfg.Services.VPN)
	}
}

func uploadOpenVPNProfileHandler(store config.Store) gin.HandlerFunc {
	type req struct {
		Name string `json:"name"`
		OVPN string `json:"ovpn"`
	}
	return func(c *gin.Context) {
		var r req
		if err := c.ShouldBindJSON(&r); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		name := strings.TrimSpace(r.Name)
		if name == "" {
			name = "client"
		}
		name = sanitizeProfileName(name)
		if name == "" {
			apiError(c, http.StatusBadRequest, "invalid profile name")
			return
		}
		ovpn := r.OVPN
		if strings.TrimSpace(ovpn) == "" {
			apiError(c, http.StatusBadRequest, "ovpn content is empty")
			return
		}
		if _, err := cpservices.ParseOpenVPNProfile([]byte(ovpn)); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}

		base := "/data/openvpn/profiles"
		if v := strings.TrimSpace(os.Getenv("CONTAIND_OPENVPN_DIR")); v != "" {
			base = v
		}
		if err := os.MkdirAll(base, 0o700); err != nil {
			internalError(c, err)
			return
		}
		// CreateTemp uses O_EXCL and never replaces an active profile artifact.
		file, err := os.CreateTemp(base, name+"-*.ovpn")
		if err != nil {
			internalError(c, err)
			return
		}
		path := file.Name()
		if _, err := file.WriteString(ovpn + "\n"); err != nil {
			file.Close()
			internalError(c, err)
			return
		}
		if err := file.Close(); err != nil {
			internalError(c, err)
			return
		}

		cfg, ok := stageCandidate(c, store, func(cfg *config.Config) bool {
			cfg.Services.VPN.OpenVPN.ConfigPath = path
			cfg.Services.VPN.OpenVPN.Managed = nil
			return true
		})
		if !ok {
			return
		}
		auditLog(c, audit.Record{Action: "services.vpn.openvpn.profile.upload", Target: name, Detail: "candidate"})
		c.JSON(http.StatusOK, gin.H{"configPath": path, "vpn": cfg.Services.VPN})
	}
}

func sanitizeProfileName(in string) string {
	in = strings.ToLower(strings.TrimSpace(in))
	var b strings.Builder
	for _, r := range in {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == '.':
			b.WriteRune(r)
		default:
		}
	}
	out := strings.Trim(b.String(), "._-")
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

func getWireGuardStatusHandler(engine any) gin.HandlerFunc {
	return func(c *gin.Context) {
		cl, ok := engine.(WireGuardStatusClient)
		if !ok || cl == nil {
			apiError(c, http.StatusServiceUnavailable, "engine wireguard status not available")
			return
		}
		iface := strings.TrimSpace(c.Query("iface"))
		ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()
		st, err := cl.GetWireGuardStatus(ctx, iface)
		if err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		c.JSON(http.StatusOK, st)
	}
}
