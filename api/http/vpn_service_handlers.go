// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	cpservices "github.com/tonylturner/containd/pkg/cp/services"
)

func getVPNHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		redacted := cfg.Services.VPN.RedactedVPNCopy()
		c.JSON(http.StatusOK, redacted)
	}
}

func setVPNHandler(store config.Store, services ServicesApplier, engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		var vpnCfg config.VPNConfig
		if err := c.ShouldBindJSON(&vpnCfg); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		vpnCfg.RestoreRedactedSecrets(cfg.Services.VPN)
		cfg.Services.VPN = vpnCfg
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		setWarningHeader(c, applyServiceRuntime(c.Request.Context(), cfg.Services, services, engine))
		auditLog(c, audit.Record{Action: "services.vpn.set", Target: "running"})
		c.JSON(http.StatusOK, cfg.Services.VPN)
	}
}

func uploadOpenVPNProfileHandler(store config.Store, services ServicesApplier, engine EngineClient) gin.HandlerFunc {
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
		ovpn := strings.TrimSpace(r.OVPN)
		if ovpn == "" {
			apiError(c, http.StatusBadRequest, "ovpn content is empty")
			return
		}
		if len(ovpn) > 1_000_000 {
			apiError(c, http.StatusRequestEntityTooLarge, "ovpn content too large")
			return
		}
		if err := ensureOpenVPNConfigForegroundString(ovpn); err != nil {
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
		path := filepath.Join(base, name+".ovpn")
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, []byte(ovpn+"\n"), 0o600); err != nil {
			internalError(c, err)
			return
		}
		if err := os.Rename(tmp, path); err != nil {
			_ = os.Remove(tmp)
			internalError(c, err)
			return
		}

		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		cfg.Services.VPN.OpenVPN.ConfigPath = path
		cfg.Services.VPN.OpenVPN.Managed = nil
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		setWarningHeader(c, applyServiceRuntime(c.Request.Context(), cfg.Services, services, engine))
		auditLog(c, audit.Record{Action: "services.vpn.openvpn.profile.upload", Target: name})
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

func ensureOpenVPNConfigForegroundString(s string) error {
	lines := strings.Split(s, "\n")
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "daemon" {
			return fmt.Errorf("openvpn profile contains 'daemon' directive; remove it (supervisor requires foreground)")
		}
	}
	return nil
}

func openVPNBaseDir() string {
	base := "/data/openvpn"
	if v := strings.TrimSpace(os.Getenv("CONTAIND_OPENVPN_DIR")); v != "" {
		base = v
		if strings.HasSuffix(base, "/profiles") {
			base = filepath.Dir(base)
		}
	}
	return base
}

func openVPNManagedServerPKIDir() string {
	return filepath.Join(openVPNBaseDir(), "managed", "server", "pki")
}

func openVPNManagedServerClientsDir() string {
	return filepath.Join(openVPNManagedServerPKIDir(), "clients")
}

func listOpenVPNClientsHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		if !cfg.Services.VPN.OpenVPN.Enabled || strings.TrimSpace(cfg.Services.VPN.OpenVPN.Mode) != "server" || cfg.Services.VPN.OpenVPN.Server == nil {
			apiError(c, http.StatusBadRequest, "openvpn server is not configured")
			return
		}
		dir := openVPNManagedServerClientsDir()
		ents, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				c.JSON(http.StatusOK, gin.H{"clients": []string{}})
				return
			}
			internalError(c, err)
			return
		}
		var out []string
		for _, e := range ents {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if strings.HasSuffix(name, ".crt") {
				out = append(out, strings.TrimSuffix(name, ".crt"))
			}
		}
		sort.Strings(out)
		c.JSON(http.StatusOK, gin.H{"clients": out})
	}
}

func createOpenVPNClientHandler(store config.Store) gin.HandlerFunc {
	type req struct {
		Name string `json:"name"`
	}
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		if !cfg.Services.VPN.OpenVPN.Enabled || strings.TrimSpace(cfg.Services.VPN.OpenVPN.Mode) != "server" || cfg.Services.VPN.OpenVPN.Server == nil {
			apiError(c, http.StatusBadRequest, "openvpn server is not configured")
			return
		}
		var r req
		if err := c.ShouldBindJSON(&r); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		name := strings.TrimSpace(r.Name)
		if name == "" {
			apiError(c, http.StatusBadRequest, "name is required")
			return
		}
		if strings.ContainsAny(name, "/\\ ") {
			apiError(c, http.StatusBadRequest, "name contains invalid characters")
			return
		}
		pkiDir := openVPNManagedServerPKIDir()
		caCertPath, caKeyPath, err := cpservices.EnsureOpenVPNCA(pkiDir)
		if err != nil {
			internalError(c, err)
			return
		}
		_, _, _ = cpservices.EnsureOpenVPNServerCert(pkiDir, caCertPath, caKeyPath)
		clientCertPath, _, err := cpservices.EnsureOpenVPNClientCert(pkiDir, caCertPath, caKeyPath, name)
		if err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		clientName := strings.TrimSuffix(filepath.Base(clientCertPath), ".crt")
		auditLog(c, audit.Record{Action: "services.vpn.openvpn.client.create", Target: clientName})
		c.JSON(http.StatusOK, gin.H{"name": clientName})
	}
}

func downloadOpenVPNClientHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		name := strings.TrimSpace(c.Param("name"))
		if name == "" {
			apiError(c, http.StatusBadRequest, "name is required")
			return
		}
		if strings.ContainsAny(name, "/\\ ") {
			apiError(c, http.StatusBadRequest, "name contains invalid characters")
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		ovpn := cfg.Services.VPN.OpenVPN
		if !ovpn.Enabled || strings.TrimSpace(ovpn.Mode) != "server" || ovpn.Server == nil {
			apiError(c, http.StatusBadRequest, "openvpn server is not configured")
			return
		}
		publicEndpoint := strings.TrimSpace(ovpn.Server.PublicEndpoint)
		if publicEndpoint == "" {
			apiError(c, http.StatusBadRequest, "openvpn.server.publicEndpoint is required to generate client profiles")
			return
		}
		proto := strings.ToLower(strings.TrimSpace(ovpn.Server.Proto))
		if proto == "" {
			proto = "udp"
		}
		port := ovpn.Server.ListenPort
		if port == 0 {
			port = 1194
		}

		pkiDir := openVPNManagedServerPKIDir()
		caCertPath, caKeyPath, err := cpservices.EnsureOpenVPNCA(pkiDir)
		if err != nil {
			internalError(c, err)
			return
		}
		_, _, _ = cpservices.EnsureOpenVPNServerCert(pkiDir, caCertPath, caKeyPath)
		clientCertPath, clientKeyPath, err := cpservices.EnsureOpenVPNClientCert(pkiDir, caCertPath, caKeyPath, name)
		if err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		caPEM, err := os.ReadFile(caCertPath)
		if err != nil {
			internalError(c, err)
			return
		}
		certPEM, err := os.ReadFile(clientCertPath)
		if err != nil {
			internalError(c, err)
			return
		}
		keyPEM, err := os.ReadFile(clientKeyPath)
		if err != nil {
			internalError(c, err)
			return
		}

		var b strings.Builder
		b.WriteString("client\n")
		b.WriteString("dev tun\n")
		b.WriteString("nobind\n")
		b.WriteString("persist-key\n")
		b.WriteString("persist-tun\n")
		b.WriteString("remote " + publicEndpoint + " " + strconv.Itoa(port) + "\n")
		if proto == "tcp" {
			b.WriteString("proto tcp-client\n")
		} else {
			b.WriteString("proto udp\n")
		}
		b.WriteString("remote-cert-tls server\n")
		b.WriteString("verb 3\n")
		writeInlineBlock(&b, "ca", caPEM)
		writeInlineBlock(&b, "cert", certPEM)
		writeInlineBlock(&b, "key", keyPEM)

		clientName := strings.TrimSuffix(filepath.Base(clientCertPath), ".crt")
		auditLog(c, audit.Record{Action: "services.vpn.openvpn.client.download", Target: clientName})
		c.Header("Content-Type", "application/x-openvpn-profile")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", clientName+".ovpn"))
		c.String(http.StatusOK, b.String())
	}
}

func writeInlineBlock(b *strings.Builder, tag string, pemBytes []byte) {
	b.WriteString("<" + tag + ">\n")
	b.Write(pemBytes)
	if len(pemBytes) == 0 || pemBytes[len(pemBytes)-1] != '\n' {
		b.WriteString("\n")
	}
	b.WriteString("</" + tag + ">\n")
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
