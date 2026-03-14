// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/tonylturner/containd/pkg/dp/dhcpd"
	"github.com/tonylturner/containd/pkg/dp/inventory"
)

func listInventoryHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		ic, ok := engine.(InventoryClient)
		if !ok || ic == nil {
			c.JSON(http.StatusOK, []inventory.DiscoveredAsset{})
			return
		}
		assets, err := ic.ListInventory(c.Request.Context())
		if err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		if assets == nil {
			assets = []inventory.DiscoveredAsset{}
		}
		c.JSON(http.StatusOK, assets)
	}
}

func getInventoryAssetHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		ic, ok := engine.(InventoryClient)
		if !ok || ic == nil {
			apiError(c, http.StatusNotFound, "inventory not available")
			return
		}
		ip := c.Param("ip")
		asset, err := ic.GetInventoryAsset(c.Request.Context(), ip)
		if err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		if asset == nil {
			apiError(c, http.StatusNotFound, "asset not found")
			return
		}
		c.JSON(http.StatusOK, asset)
	}
}

func clearInventoryHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		ic, ok := engine.(InventoryClient)
		if !ok || ic == nil {
			apiError(c, http.StatusNotImplemented, "inventory not available")
			return
		}
		if err := ic.ClearInventory(c.Request.Context()); err != nil {
			apiError(c, http.StatusInternalServerError, err.Error())
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "cleared"})
	}
}

func dhcpLeasesHandler(engine any) gin.HandlerFunc {
	type resp struct {
		Leases []dhcpd.Lease `json:"leases"`
	}
	return func(c *gin.Context) {
		cl, ok := engine.(DHCPLeasesClient)
		if !ok || cl == nil {
			apiError(c, http.StatusServiceUnavailable, "engine dhcp leases not available")
			return
		}
		leases, err := cl.ListDHCPLeases(c.Request.Context())
		if err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		c.JSON(http.StatusOK, resp{Leases: leases})
	}
}
