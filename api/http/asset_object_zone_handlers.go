// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func listAssetsHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, cfg.Assets)
	}
}

func createAssetHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var a config.Asset
		if err := c.ShouldBindJSON(&a); err != nil || a.ID == "" {
			apiError(c, http.StatusBadRequest, "invalid asset payload")
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		for _, existing := range cfg.Assets {
			if existing.ID == a.ID {
				apiError(c, http.StatusBadRequest, "asset already exists")
				return
			}
			if existing.Name != "" && existing.Name == a.Name {
				apiError(c, http.StatusBadRequest, "asset name already exists")
				return
			}
		}
		cfg.Assets = append(cfg.Assets, a)
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "assets.create", Target: a.ID})
		c.JSON(http.StatusOK, a)
	}
}

func updateAssetHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		var a config.Asset
		if err := c.ShouldBindJSON(&a); err != nil {
			apiError(c, http.StatusBadRequest, "invalid asset payload")
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		updated := false
		for i, existing := range cfg.Assets {
			if existing.ID == id {
				if a.ID == "" {
					a.ID = existing.ID
				}
				if a.Name == "" {
					a.Name = existing.Name
				}
				cfg.Assets[i] = a
				updated = true
				break
			}
		}
		if !updated {
			apiError(c, http.StatusNotFound, "asset not found")
			return
		}
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "assets.update", Target: id})
		c.JSON(http.StatusOK, a)
	}
}

func deleteAssetHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		original := len(cfg.Assets)
		filtered := make([]config.Asset, 0, len(cfg.Assets))
		for _, a := range cfg.Assets {
			if a.ID != id {
				filtered = append(filtered, a)
			}
		}
		if len(filtered) == original {
			apiError(c, http.StatusNotFound, "asset not found")
			return
		}
		cfg.Assets = filtered
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			internalError(c, err)
			return
		}
		auditLog(c, audit.Record{Action: "assets.delete", Target: id})
		c.Status(http.StatusNoContent)
	}
}

func listObjectsHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, cfg.Objects)
	}
}

func createObjectHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var obj config.Object
		if err := c.ShouldBindJSON(&obj); err != nil || obj.ID == "" {
			apiError(c, http.StatusBadRequest, "invalid object payload")
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		for _, existing := range cfg.Objects {
			if existing.ID == obj.ID {
				apiError(c, http.StatusBadRequest, "object already exists")
				return
			}
			if existing.Name != "" && existing.Name == obj.Name {
				apiError(c, http.StatusBadRequest, "object name already exists")
				return
			}
		}
		cfg.Objects = append(cfg.Objects, obj)
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "objects.create", Target: obj.ID})
		c.JSON(http.StatusOK, obj)
	}
}

func updateObjectHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		var obj config.Object
		if err := c.ShouldBindJSON(&obj); err != nil {
			apiError(c, http.StatusBadRequest, "invalid object payload")
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		updated := false
		for i, existing := range cfg.Objects {
			if existing.ID == id {
				if obj.ID == "" {
					obj.ID = existing.ID
				}
				if obj.Name == "" {
					obj.Name = existing.Name
				}
				if obj.Type == "" {
					obj.Type = existing.Type
				}
				if obj.Addresses == nil {
					obj.Addresses = existing.Addresses
				}
				if obj.Members == nil {
					obj.Members = existing.Members
				}
				if obj.Protocols == nil {
					obj.Protocols = existing.Protocols
				}
				if obj.Tags == nil {
					obj.Tags = existing.Tags
				}
				cfg.Objects[i] = obj
				updated = true
				break
			}
		}
		if !updated {
			apiError(c, http.StatusNotFound, "object not found")
			return
		}
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "objects.update", Target: id})
		c.JSON(http.StatusOK, obj)
	}
}

func deleteObjectHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		original := len(cfg.Objects)
		filtered := make([]config.Object, 0, len(cfg.Objects))
		for _, obj := range cfg.Objects {
			if obj.ID != id {
				filtered = append(filtered, obj)
			}
		}
		if len(filtered) == original {
			apiError(c, http.StatusNotFound, "object not found")
			return
		}
		cfg.Objects = filtered
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			internalError(c, err)
			return
		}
		auditLog(c, audit.Record{Action: "objects.delete", Target: id})
		c.Status(http.StatusNoContent)
	}
}

func listZonesHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, cfg.Zones)
	}
}

func createZoneHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var z config.Zone
		if err := c.ShouldBindJSON(&z); err != nil || z.Name == "" {
			apiError(c, http.StatusBadRequest, "invalid zone payload")
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		for _, existing := range cfg.Zones {
			if existing.Name == z.Name {
				apiError(c, http.StatusBadRequest, "zone already exists")
				return
			}
		}
		cfg.Zones = append(cfg.Zones, z)
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
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
			internalError(c, err)
			return
		}
		for _, iface := range cfg.Interfaces {
			if iface.Zone == name {
				apiError(c, http.StatusBadRequest, "zone in use by interface")
				return
			}
		}
		for _, rule := range cfg.Firewall.Rules {
			for _, z := range append(rule.SourceZones, rule.DestZones...) {
				if z == name {
					apiError(c, http.StatusBadRequest, "zone in use by firewall rule")
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
			apiError(c, http.StatusNotFound, "zone not found")
			return
		}
		cfg.Zones = filtered
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			internalError(c, err)
			return
		}
		c.Status(http.StatusNoContent)
	}
}

func updateZoneHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		name := c.Param("name")
		patch, err := readZonePatch(c)
		if err != nil {
			apiError(c, http.StatusBadRequest, "invalid zone payload")
			return
		}

		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		idx := zoneIndexByName(cfg.Zones, name)
		if idx < 0 {
			apiError(c, http.StatusNotFound, "zone not found")
			return
		}
		z := &cfg.Zones[idx]
		applyZonePatch(z, patch)

		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		c.JSON(http.StatusOK, *z)
	}
}

func readZonePatch(c *gin.Context) (map[string]interface{}, error) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return nil, err
	}
	var patch map[string]interface{}
	if err := json.Unmarshal(body, &patch); err != nil {
		return nil, err
	}
	return patch, nil
}

func zoneIndexByName(zones []config.Zone, name string) int {
	for i, existing := range zones {
		if existing.Name == name {
			return i
		}
	}
	return -1
}

func applyZonePatch(z *config.Zone, patch map[string]interface{}) {
	applyZoneStringField(patch, "name", func(v string) { z.Name = v })
	applyZoneStringField(patch, "alias", func(v string) { z.Alias = v })
	applyZoneStringField(patch, "description", func(v string) { z.Description = v })
	applyZoneStringField(patch, "consequence", func(v string) { z.Consequence = v })
	if v, ok := patch["slTarget"]; ok {
		if f, ok := v.(float64); ok {
			z.SLTarget = int(f)
		}
	}
	if overrides, ok := patch["slOverrides"].(map[string]interface{}); ok {
		applyZoneOverrides(z, overrides)
	}
}

func applyZoneStringField(patch map[string]interface{}, key string, apply func(string)) {
	if v, ok := patch[key].(string); ok {
		apply(v)
	}
}

func applyZoneOverrides(z *config.Zone, overrides map[string]interface{}) {
	if z.SLOverrides == nil {
		z.SLOverrides = make(map[string]bool)
	}
	for k, val := range overrides {
		if b, ok := val.(bool); ok {
			z.SLOverrides[k] = b
		}
	}
}
