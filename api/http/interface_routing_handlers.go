// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/tonylturner/containd/pkg/common/protection"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func listInterfacesHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := readCandidate(c, store)
		if err != nil {
			internalError(c, err)
			return
		}
		configCollectionJSON(c, cfg.Interfaces)
	}
}

func interfaceStateHandler(engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		if engine == nil {
			apiError(c, http.StatusServiceUnavailable, "engine interface state unavailable")
			return
		}
		st, err := engine.ListInterfaceState(c.Request.Context())
		if err != nil {
			apiError(c, http.StatusServiceUnavailable, "engine interface state unavailable")
			return
		}
		if st == nil {
			st = []config.InterfaceState{}
		}
		c.JSON(http.StatusOK, st)
	}
}

func interfacesReconcileHandler(store config.Store, engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		if engine == nil {
			apiError(c, http.StatusBadRequest, "engine unavailable")
			return
		}
		var req struct {
			Confirm string `json:"confirm"`
		}
		if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Confirm) != "REPLACE" {
			apiError(c, http.StatusBadRequest, "confirm required: set {\"confirm\":\"REPLACE\"}")
			return
		}
		coordinator, ok := requestCoordinator(c)
		if !ok {
			return
		}
		c.Header(revisionHeader, "")
		if err := coordinator.Reconcile(c.Request.Context(), protection.SubsystemInterfaces); err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "interfaces.reconcile", Target: "engine"})
		c.JSON(http.StatusOK, gin.H{"status": "reconciled"})
	}
}

func createInterfaceHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var iface config.Interface
		if err := c.ShouldBindJSON(&iface); err != nil || iface.Name == "" {
			apiError(c, http.StatusBadRequest, "invalid interface payload")
			return
		}
		_, ok := stageCandidate(c, store, func(cfg *config.Config) bool {
			for _, existing := range cfg.Interfaces {
				if existing.Name == iface.Name {
					apiError(c, http.StatusBadRequest, "interface already exists")
					return false
				}
			}
			cfg.Interfaces = append(cfg.Interfaces, iface)
			return true
		})
		if !ok {
			return
		}
		auditLog(c, audit.Record{Action: "interfaces.create", Target: iface.Name, Detail: "candidate"})
		c.JSON(http.StatusOK, iface)
	}
}

func deleteInterfaceHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		name := c.Param("name")
		_, ok := stageCandidate(c, store, func(cfg *config.Config) bool {
			original := len(cfg.Interfaces)
			filtered := make([]config.Interface, 0, len(cfg.Interfaces))
			for _, i := range cfg.Interfaces {
				if i.Name != name {
					filtered = append(filtered, i)
				}
			}
			if len(filtered) == original {
				apiError(c, http.StatusNotFound, "interface not found")
				return false
			}
			cfg.Interfaces = filtered
			return true
		})
		if !ok {
			return
		}
		auditLog(c, audit.Record{Action: "interfaces.delete", Target: name, Detail: "candidate"})
		c.Status(http.StatusNoContent)
	}
}

func updateInterfaceHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		name := c.Param("name")
		var patch map[string]json.RawMessage
		var iface config.Interface
		if err := c.ShouldBindJSON(&patch); err != nil || patch == nil {
			apiError(c, http.StatusBadRequest, "invalid interface payload")
			return
		}
		if _, err := mergeInterfacePatch(config.Interface{}, patch); err != nil {
			apiError(c, http.StatusBadRequest, "invalid interface payload")
			return
		}
		_, ok := stageCandidate(c, store, func(cfg *config.Config) bool {
			for i, existing := range cfg.Interfaces {
				if existing.Name == name {
					var err error
					iface, err = mergeInterfacePatch(existing, patch)
					if err != nil {
						apiError(c, http.StatusBadRequest, "invalid interface payload")
						return false
					}
					cfg.Interfaces[i] = iface
					return true
				}
			}
			apiError(c, http.StatusNotFound, "interface not found")
			return false
		})
		if !ok {
			return
		}
		auditLog(c, audit.Record{Action: "interfaces.update", Target: name, Detail: "candidate"})
		c.JSON(http.StatusOK, iface)
	}
}

// Merge top-level fields, decoding into a fresh value so explicit null clears
// scalars and access as well as slices. A supplied access object replaces it.
func mergeInterfacePatch(existing config.Interface, patch map[string]json.RawMessage) (config.Interface, error) {
	var iface config.Interface
	data, err := json.Marshal(existing)
	if err != nil {
		return iface, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return iface, err
	}
	for key, value := range patch {
		fields[key] = value
	}
	data, err = json.Marshal(fields)
	if err != nil {
		return iface, err
	}
	err = json.Unmarshal(data, &iface)
	return iface, err
}

func getRoutingHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := readCandidate(c, store)
		if err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, cfg.Routing)
	}
}

func setRoutingHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		var routingCfg config.RoutingConfig
		if err := c.ShouldBindJSON(&routingCfg); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		cfg, ok := stageCandidate(c, store, func(cfg *config.Config) bool {
			cfg.Routing = routingCfg
			return true
		})
		if !ok {
			return
		}
		auditLog(c, audit.Record{Action: "routing.set", Target: "config", Detail: "candidate"})
		c.JSON(http.StatusOK, cfg.Routing)
	}
}

func routingReconcileHandler(store config.Store, engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		if engine == nil {
			apiError(c, http.StatusBadRequest, "engine unavailable")
			return
		}
		var req struct {
			Confirm string `json:"confirm"`
		}
		if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Confirm) != "REPLACE" {
			apiError(c, http.StatusBadRequest, "confirm required: set {\"confirm\":\"REPLACE\"}")
			return
		}
		coordinator, ok := requestCoordinator(c)
		if !ok {
			return
		}
		c.Header(revisionHeader, "")
		if err := coordinator.Reconcile(c.Request.Context(), protection.SubsystemRouting); err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "routing.reconcile", Target: "engine"})
		c.JSON(http.StatusOK, gin.H{"status": "reconciled"})
	}
}
