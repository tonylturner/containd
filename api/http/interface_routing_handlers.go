// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func listInterfacesHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, cfg.Interfaces)
	}
}

func interfaceStateHandler(store config.Store, engine EngineClient) gin.HandlerFunc {
	return func(c *gin.Context) {
		if _, err := loadOrInitConfig(c.Request.Context(), store); err != nil {
			internalError(c, err)
			return
		}
		if engine == nil {
			c.JSON(http.StatusOK, []config.InterfaceState{})
			return
		}
		st, err := engine.ListInterfaceState(c.Request.Context())
		if err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		c.JSON(http.StatusOK, st)
	}
}

func interfacesAssignHandler(store config.Store, engine EngineClient, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		if engine == nil {
			apiError(c, http.StatusBadRequest, "engine unavailable")
			return
		}
		req, err := bindInterfaceAssignRequest(c)
		if err != nil {
			apiError(c, http.StatusBadRequest, "invalid request")
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		state, err := engine.ListInterfaceState(c.Request.Context())
		if err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		deviceSet := interfaceDeviceSet(state)

		ifaceByName := map[string]*config.Interface{}
		for i := range cfg.Interfaces {
			ifaceByName[cfg.Interfaces[i].Name] = &cfg.Interfaces[i]
		}

		assignments, err := resolveInterfaceAssignments(cfg.Interfaces, state, req)
		if err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		if err := validateInterfaceAssignments(assignments, ifaceByName, deviceSet); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}

		for logical, dev := range assignments {
			ifaceByName[logical].Device = dev
		}
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		warnings, err := applyRunningConfig(c.Request.Context(), store, engine, services)
		if err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		setWarningHeader(c, warnings)
		auditLog(c, audit.Record{Action: "interfaces.assign", Target: "config"})
		c.JSON(http.StatusOK, gin.H{"interfaces": cfg.Interfaces})
	}
}

type interfaceAssignRequest struct {
	Mode     string            `json:"mode"`
	Mappings map[string]string `json:"mappings"`
}

func bindInterfaceAssignRequest(c *gin.Context) (interfaceAssignRequest, error) {
	var req interfaceAssignRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		return interfaceAssignRequest{}, err
	}
	req.Mode = normalizedInterfaceAssignMode(req)
	return req, nil
}

func normalizedInterfaceAssignMode(req interfaceAssignRequest) string {
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "" && len(req.Mappings) > 0 {
		return "explicit"
	}
	return mode
}

func resolveInterfaceAssignments(ifaces []config.Interface, state []config.InterfaceState, req interfaceAssignRequest) (map[string]string, error) {
	switch req.Mode {
	case "auto":
		return computeDefaultInterfaceAssignments(ifaces, state, autoAssignOptions{
			AllowFallback:     true,
			DefaultRouteIface: detectKernelDefaultRouteIface(),
		})
	case "explicit":
		return normalizedInterfaceMappings(req.Mappings)
	default:
		return nil, fmt.Errorf("mode must be auto or explicit")
	}
}

func normalizedInterfaceMappings(mappings map[string]string) (map[string]string, error) {
	if len(mappings) == 0 {
		return nil, fmt.Errorf("mappings required")
	}
	assignments := map[string]string{}
	for k, v := range mappings {
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k == "" {
			continue
		}
		if strings.EqualFold(v, "none") || v == "-" {
			v = ""
		}
		assignments[k] = v
	}
	return assignments, nil
}

func validateInterfaceAssignments(assignments map[string]string, ifaceByName map[string]*config.Interface, deviceSet map[string]struct{}) error {
	used := map[string]string{}
	for logical, dev := range assignments {
		if _, ok := ifaceByName[logical]; !ok {
			return fmt.Errorf("unknown interface: %s", logical)
		}
		if dev == "" {
			continue
		}
		if _, ok := deviceSet[dev]; !ok {
			return fmt.Errorf("unknown kernel device: %s", dev)
		}
		if prev, ok := used[dev]; ok && prev != logical {
			return fmt.Errorf("device %s already assigned to %s", dev, prev)
		}
		used[dev] = logical
	}
	return nil
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
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		if err := engine.ConfigureInterfacesReplace(c.Request.Context(), cfg.Interfaces); err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "interfaces.reconcile", Target: "engine"})
		c.JSON(http.StatusOK, gin.H{"status": "reconciled"})
	}
}

func createInterfaceHandler(store config.Store, engine EngineClient, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		var iface config.Interface
		if err := c.ShouldBindJSON(&iface); err != nil || iface.Name == "" {
			apiError(c, http.StatusBadRequest, "invalid interface payload")
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		for _, existing := range cfg.Interfaces {
			if existing.Name == iface.Name {
				apiError(c, http.StatusBadRequest, "interface already exists")
				return
			}
		}
		cfg.Interfaces = append(cfg.Interfaces, iface)
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		if engine != nil {
			warnings, err := applyRunningConfig(c.Request.Context(), store, engine, services)
			if err != nil {
				apiError(c, http.StatusBadGateway, err.Error())
				return
			}
			setWarningHeader(c, warnings)
		}
		auditLog(c, audit.Record{Action: "interfaces.create", Target: iface.Name})
		c.JSON(http.StatusOK, iface)
	}
}

func deleteInterfaceHandler(store config.Store, engine EngineClient, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		name := c.Param("name")
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
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
			apiError(c, http.StatusNotFound, "interface not found")
			return
		}
		cfg.Interfaces = filtered
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			internalError(c, err)
			return
		}
		if engine != nil {
			warnings, err := applyRunningConfig(c.Request.Context(), store, engine, services)
			if err != nil {
				apiError(c, http.StatusBadGateway, err.Error())
				return
			}
			setWarningHeader(c, warnings)
		}
		auditLog(c, audit.Record{Action: "interfaces.delete", Target: name})
		c.Status(http.StatusNoContent)
	}
}

func updateInterfaceHandler(store config.Store, engine EngineClient, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		name := c.Param("name")
		var iface config.Interface
		if err := c.ShouldBindJSON(&iface); err != nil {
			apiError(c, http.StatusBadRequest, "invalid interface payload")
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		isAccessUnset := func(a config.InterfaceAccess) bool {
			return a.Mgmt == nil && a.HTTP == nil && a.HTTPS == nil && a.SSH == nil
		}
		updated := false
		for i, existing := range cfg.Interfaces {
			if existing.Name == name {
				if iface.Name == "" {
					iface.Name = existing.Name
				}
				if strings.TrimSpace(iface.Device) == "" {
					iface.Device = existing.Device
				}
				if strings.TrimSpace(iface.Zone) == "" {
					iface.Zone = existing.Zone
				}
				if iface.Addresses == nil {
					iface.Addresses = existing.Addresses
				}
				if isAccessUnset(iface.Access) {
					iface.Access = existing.Access
				}
				cfg.Interfaces[i] = iface
				updated = true
				break
			}
		}
		if !updated {
			apiError(c, http.StatusNotFound, "interface not found")
			return
		}
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		if engine != nil {
			warnings, err := applyRunningConfig(c.Request.Context(), store, engine, services)
			if err != nil {
				apiError(c, http.StatusBadGateway, err.Error())
				return
			}
			setWarningHeader(c, warnings)
		}
		auditLog(c, audit.Record{Action: "interfaces.update", Target: name})
		c.JSON(http.StatusOK, iface)
	}
}

func getRoutingHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		c.JSON(http.StatusOK, cfg.Routing)
	}
}

func setRoutingHandler(store config.Store, engine EngineClient, services ServicesApplier) gin.HandlerFunc {
	return func(c *gin.Context) {
		var routingCfg config.RoutingConfig
		if err := c.ShouldBindJSON(&routingCfg); err != nil {
			apiErrorDetail(c, http.StatusBadRequest, "invalid JSON", err.Error())
			return
		}
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		cfg.Routing = routingCfg
		if err := store.Save(c.Request.Context(), cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
			return
		}
		warnings, err := applyRunningConfig(c.Request.Context(), store, engine, services)
		if err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		setWarningHeader(c, warnings)
		auditLog(c, audit.Record{Action: "routing.set", Target: "config"})
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
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		if err := engine.ConfigureRoutingReplace(c.Request.Context(), cfg.Routing); err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		auditLog(c, audit.Record{Action: "routing.reconcile", Target: "engine"})
		c.JSON(http.StatusOK, gin.H{"status": "reconciled"})
	}
}
