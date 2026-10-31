// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/tonylturner/containd/pkg/cp/audit"
	cpservices "github.com/tonylturner/containd/pkg/cp/services"
)

func openVPNClients(c *gin.Context, services ServicesApplier) (cpservices.OpenVPNClients, bool) {
	clients, ok := services.(cpservices.OpenVPNClients)
	if !ok || clients == nil {
		apiError(c, http.StatusServiceUnavailable, "openvpn credential authority unavailable")
		return nil, false
	}
	return clients, true
}

func openVPNClientError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, cpservices.ErrOpenVPNUnknownCredential):
		apiError(c, http.StatusNotFound, err.Error())
	case errors.Is(err, cpservices.ErrOpenVPNClientNameIssued),
		errors.Is(err, cpservices.ErrOpenVPNCredentialRevoked),
		errors.Is(err, cpservices.ErrOpenVPNServerNotActive):
		apiError(c, http.StatusConflict, err.Error())
	case errors.Is(err, cpservices.ErrOpenVPNInvalidClientName):
		apiError(c, http.StatusBadRequest, err.Error())
	default:
		internalError(c, err)
	}
}

func listOpenVPNClientsHandler(services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		clients, ok := openVPNClients(c, services)
		if !ok {
			return
		}
		credentials, err := clients.ListOpenVPNClients(c.Request.Context())
		if err != nil {
			openVPNClientError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"clients": credentials})
	}
}

func createOpenVPNClientHandler(services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		clients, ok := openVPNClients(c, services)
		if !ok {
			return
		}
		var req struct {
			Name string `json:"name"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		credential, err := clients.CreateOpenVPNClient(c.Request.Context(), req.Name)
		if err != nil {
			openVPNClientError(c, err)
			return
		}
		auditLog(c, audit.Record{Action: "services.vpn.openvpn.client.create", Target: credential.ID})
		c.JSON(http.StatusOK, credential)
	}
}

func downloadOpenVPNClientHandler(services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		clients, ok := openVPNClients(c, services)
		if !ok {
			return
		}
		id := c.Param("id")
		profile, err := clients.DownloadOpenVPNClient(c.Request.Context(), id)
		if err != nil {
			openVPNClientError(c, err)
			return
		}
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", id+".ovpn"))
		c.Data(http.StatusOK, "application/x-openvpn-profile", profile)
	}
}

func revokeOpenVPNClientHandler(services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		clients, ok := openVPNClients(c, services)
		if !ok {
			return
		}
		result, err := clients.RevokeOpenVPNClient(c.Request.Context(), c.Param("id"))
		if result.Revoked {
			auditLog(c, audit.Record{
				Action: "services.vpn.openvpn.client.revoke", Target: result.Credential.ID,
				Detail: fmt.Sprintf("revoked=%t applied=%t", result.Revoked, result.Applied),
			})
		}
		if result.Revoked && (err != nil || !result.Applied) {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"credential": result.Credential, "revoked": true, "applied": result.Applied,
				"error": "revoked, runtime not confirmed",
			})
			return
		}
		if err != nil {
			openVPNClientError(c, err)
			return
		}
		if !result.Revoked || !result.Applied {
			apiError(c, http.StatusServiceUnavailable, "revocation not confirmed")
			return
		}
		c.JSON(http.StatusOK, result)
	}
}
