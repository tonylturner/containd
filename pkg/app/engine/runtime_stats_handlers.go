// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package engineapp

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/engine"
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/stats"
)

func eventsHandler(dpEngine *engine.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q, filtered, err := events.ParseQuery(r.URL.Query())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if filtered {
			writeJSON(w, dpEngine.Events().QueryTelemetry(q))
			return
		}
		list := dpEngine.Events().ListTelemetry(q.Limit)
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
		inv := dpEngine.Inventory()
		if inv == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			writeJSON(w, map[string]string{"error": "inventory unavailable"})
			return
		}
		switch r.Method {
		case http.MethodGet:
			if r.URL.Query().Get("section") == "iec104" {
				writeJSON(w, inv.SnapshotIEC104())
				return
			}
			writeJSON(w, inv.List())
		case http.MethodDelete:
			inv.Clear()
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
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			writeJSON(w, map[string]string{"error": "inventory unavailable"})
			return
		}
		assets := inv.GetAssets(ip)
		if len(assets) == 0 {
			http.Error(w, "asset not found", http.StatusNotFound)
			return
		}
		writeJSON(w, assets)
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
