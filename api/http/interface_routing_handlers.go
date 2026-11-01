// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
)

func listInterfacesHandler(store config.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, err := store.LoadCandidate(c.Request.Context())
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

func interfacesAssignHandler(store config.Store, engine EngineClient) gin.HandlerFunc {
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
		state, err := engine.ListInterfaceState(c.Request.Context())
		if err != nil {
			apiError(c, http.StatusBadGateway, err.Error())
			return
		}
		deviceSet := interfaceDeviceSet(state)
		defaultRouteIface := ""
		if req.Mode == "auto" {
			defaultRouteIface = detectKernelDefaultRouteIface()
		}
		cfg, ok := stageCandidate(c, store, func(cfg *config.Config) bool {
			ifaceByName := map[string]*config.Interface{}
			for i := range cfg.Interfaces {
				ifaceByName[cfg.Interfaces[i].Name] = &cfg.Interfaces[i]
			}

			assignments, err := resolveInterfaceAssignments(cfg.Interfaces, state, req, defaultRouteIface, config.ReservationForStore(store))
			if err != nil {
				apiError(c, http.StatusBadRequest, err.Error())
				return false
			}
			if err := validateInterfaceAssignments(assignments, ifaceByName, deviceSet); err != nil {
				apiError(c, http.StatusBadRequest, err.Error())
				return false
			}

			for logical, dev := range assignments {
				ifaceByName[logical].Device = dev
			}
			return true
		})
		if !ok {
			return
		}
		auditLog(c, audit.Record{Action: "interfaces.assign", Target: "config", Detail: "candidate"})
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

func resolveInterfaceAssignments(ifaces []config.Interface, state []config.InterfaceState, req interfaceAssignRequest, defaultRouteIface string, r *mgmtpath.Reservation) (map[string]string, error) {
	switch req.Mode {
	case "auto":
		return computeDefaultInterfaceAssignments(ifaces, state, autoAssignOptions{
			Reservation:       r,
			AllowFallback:     true,
			DefaultRouteIface: defaultRouteIface,
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
		runningConfigApplyMu.Lock()
		defer runningConfigApplyMu.Unlock()
		cfg, err := loadOrInitConfig(c.Request.Context(), store)
		if err != nil {
			internalError(c, err)
			return
		}
		if _, _, err := config.EffectiveForStore(store, cfg); err != nil {
			apiError(c, http.StatusBadRequest, err.Error())
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
		cfg, err := store.LoadCandidate(c.Request.Context())
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
		runningConfigApplyMu.Lock()
		defer runningConfigApplyMu.Unlock()
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
