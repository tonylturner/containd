// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapp

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/netcfg"
)

func interfacesHandler(logger *zap.SugaredLogger, ownership *ownershipManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		mode := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("mode")))
		replace := mode == "replace"
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}
		var ifaces []config.Interface
		if err := json.Unmarshal(body, &ifaces); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if replace {
			if err := netcfg.ApplyInterfacesReplace(ctx, ifaces); err != nil {
				logger.Errorf("apply interfaces(replace) failed: %v", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		} else {
			if err := netcfg.ApplyInterfaces(ctx, ifaces); err != nil {
				logger.Errorf("apply interfaces failed: %v", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		if ownership != nil {
			ownership.setInterfaces(ifaces)
		}
		writeJSON(w, map[string]any{"status": "applied"})
	}
}

func interfacesStateHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		sysIfaces, err := net.Interfaces()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out := make([]config.InterfaceState, 0, len(sysIfaces))
		for _, si := range sysIfaces {
			addrs, _ := si.Addrs()
			ss := make([]string, 0, len(addrs))
			for _, a := range addrs {
				if s := strings.TrimSpace(a.String()); s != "" {
					ss = append(ss, s)
				}
			}
			sort.Strings(ss)
			out = append(out, config.InterfaceState{
				Name:  si.Name,
				Index: si.Index,
				Up:    (si.Flags & net.FlagUp) != 0,
				MTU:   si.MTU,
				MAC:   strings.TrimSpace(si.HardwareAddr.String()),
				Addrs: ss,
			})
		}
		writeJSON(w, out)
	}
}

func routingHandler(logger *zap.SugaredLogger, ownership *ownershipManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		mode := strings.TrimSpace(r.URL.Query().Get("mode"))
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}
		var routing config.RoutingConfig
		if err := json.Unmarshal(body, &routing); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		resolved := routing
		if ownership != nil {
			resolved = resolveRoutingIfaces(routing, ownership.currentInterfaces())
		}
		var applyErr error
		if strings.EqualFold(mode, "replace") {
			applyErr = netcfg.ApplyRoutingReplace(ctx, resolved)
		} else {
			applyErr = netcfg.ApplyRouting(ctx, resolved)
		}
		if applyErr != nil {
			logger.Errorf("apply routing failed: %v", applyErr)
			http.Error(w, applyErr.Error(), http.StatusBadRequest)
			return
		}
		if ownership != nil {
			ownership.setRouting(routing)
		}
		writeJSON(w, map[string]any{"status": "applied"})
	}
}

func ownershipHandler(ownership *ownershipManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, ownershipStatus(ownership))
	}
}

func firstNonEmpty(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}
