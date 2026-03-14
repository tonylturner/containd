// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapp

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/inventory"
	"github.com/tonylturner/containd/pkg/dp/stats"
)

func eventsHandler(dpEngine *engine.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit := parseLimit(r, 500)
		list := dpEngine.Events().List(limit)
		writeJSON(w, list)
	}
}

func flowsHandler(dpEngine *engine.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit := parseLimit(r, 200)
		list := dpEngine.Events().Flows(limit)
		writeJSON(w, list)
	}
}

func protoStatsHandler(dpEngine *engine.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		list := dpEngine.ProtoStats()
		if list == nil {
			list = []stats.ProtoStats{}
		}
		writeJSON(w, list)
	}
}

func topTalkersHandler(dpEngine *engine.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		n := 10
		if q := r.URL.Query().Get("n"); q != "" {
			if v, err := strconv.Atoi(q); err == nil && v > 0 {
				n = v
			}
		}
		list := dpEngine.TopTalkers(n)
		if list == nil {
			list = []stats.FlowStats{}
		}
		writeJSON(w, list)
	}
}

func inventoryHandler(dpEngine *engine.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			var list []inventory.DiscoveredAsset
			if inv := dpEngine.Inventory(); inv != nil {
				list = inv.List()
			}
			if list == nil {
				list = []inventory.DiscoveredAsset{}
			}
			writeJSON(w, list)
		case http.MethodDelete:
			if inv := dpEngine.Inventory(); inv != nil {
				inv.Clear()
			}
			writeJSON(w, map[string]string{"status": "cleared"})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func inventoryItemHandler(dpEngine *engine.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		ip := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/internal/inventory/"))
		if ip == "" {
			http.Error(w, "missing asset ip", http.StatusBadRequest)
			return
		}
		inv := dpEngine.Inventory()
		if inv == nil {
			http.Error(w, "inventory unavailable", http.StatusServiceUnavailable)
			return
		}
		asset, ok := inv.Get(ip)
		if !ok {
			http.Error(w, "asset not found", http.StatusNotFound)
			return
		}
		writeJSON(w, asset)
	}
}

func parseLimit(r *http.Request, def int) int {
	q := r.URL.Query().Get("limit")
	if q == "" {
		return def
	}
	if v, err := strconv.Atoi(q); err == nil && v > 0 {
		return v
	}
	return def
}
