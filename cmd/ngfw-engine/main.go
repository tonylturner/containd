package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/containd/containd/pkg/common/logging"
	"github.com/containd/containd/pkg/cp/config"
	"github.com/containd/containd/pkg/dp/capture"
	"github.com/containd/containd/pkg/dp/dpi"
	"github.com/containd/containd/pkg/dp/engine"
	"github.com/containd/containd/pkg/dp/enforce"
	"github.com/containd/containd/pkg/dp/flow"
	"github.com/containd/containd/pkg/dp/rules"
)

type healthResponse struct {
	Status     string `json:"status"`
	Component  string `json:"component"`
	Build      string `json:"build"`
	CommitHash string `json:"commitHash,omitempty"`
}

func main() {
	addr := addrFromEnv("NGFW_ENGINE_ADDR", ":8081")
	logger := logging.New("[engine]")

	ifaces := []string{}
	enforceEnabled := false
	enforceTable := "containd"

	dpEngine, err := engine.New(engine.Config{
		Capture: capture.Config{Interfaces: ifaces},
		Enforce: engine.EnforceConfig{
			Enabled:   enforceEnabled,
			TableName: enforceTable,
			Applier:   enforce.NewNftApplier(),
			Updater:   enforce.NewNftUpdater(enforceTable),
		},
	})
	if err != nil {
		logger.Fatalf("failed to init dp engine: %v", err)
	}
	// Start capture (no-op if no interfaces).
	go func() {
		if err := dpEngine.Start(context.Background()); err != nil {
			logger.Printf("capture start failed: %v", err)
		}
	}()

	if os.Getenv("NGFW_DPI_MOCK") == "1" {
		go mockDPI(logger, dpEngine)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/internal/apply_rules", applyRulesHandler(dpEngine))
	mux.HandleFunc("/internal/rules", getRulesHandler(dpEngine))
	mux.HandleFunc("/internal/config", configHandler(logger, dpEngine))
	mux.HandleFunc("/internal/events", eventsHandler(dpEngine))
	mux.HandleFunc("/internal/flows", flowsHandler(dpEngine))

	logger.Printf("ngfw-engine starting on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		logger.Fatalf("server exited: %v", err)
	}
}

func addrFromEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	resp := healthResponse{
		Status:    "ok",
		Component: "ngfw-engine",
		Build:     "dev",
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func applyRulesHandler(dpEngine *engine.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read body", http.StatusBadRequest)
			return
		}
		var snap rules.Snapshot
		if err := json.Unmarshal(body, &snap); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if err := dpEngine.ApplyRules(ctx, snap); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "applied"})
	}
}

func getRulesHandler(dpEngine *engine.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		snap := dpEngine.CurrentRules()
		if snap == nil {
			http.Error(w, "no rules loaded", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(snap)
	}
}

func configHandler(logger *log.Logger, dpEngine *engine.Engine) http.HandlerFunc {
	var current config.DataPlaneConfig
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(current)
			return
		case http.MethodPost:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "failed to read body", http.StatusBadRequest)
				return
			}
			var dp config.DataPlaneConfig
			if err := json.Unmarshal(body, &dp); err != nil {
				http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
				return
			}
			// Reconfigure by rebuilding the engine instance.
			current = dp
			newEngine, err := engine.New(engine.Config{
				Capture: capture.Config{Interfaces: dp.CaptureInterfaces},
				Enforce: engine.EnforceConfig{
					Enabled:   dp.Enforcement,
					TableName: firstNonEmpty(dp.EnforceTable, "containd"),
					Applier:   enforce.NewNftApplier(),
					Updater:   enforce.NewNftUpdater(firstNonEmpty(dp.EnforceTable, "containd")),
				},
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			// Swap pointer by copying fields.
			*dpEngine = *newEngine
			go func() {
				if err := dpEngine.Start(context.Background()); err != nil {
					logger.Printf("capture start failed: %v", err)
				}
			}()
			if dp.DPIMock {
				go mockDPI(logger, dpEngine)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "configured"})
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}
}

func firstNonEmpty(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func parseListEnv(key string) []string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func mockDPI(logger *log.Logger, dpEngine *engine.Engine) {
	raw := []byte{
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x06,
		0x01,
		0x03,
		0x00, 0x00,
		0x00, 0x02,
	}
	key := flow.Key{
		SrcIP:   net.ParseIP("10.0.0.1"),
		DstIP:   net.ParseIP("10.0.0.2"),
		SrcPort: 12345,
		DstPort: 502,
		Proto:   6,
		Dir:     flow.DirForward,
	}
	state := flow.NewState(key, time.Now())
	t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for range t.C {
			pkt := &dpi.ParsedPacket{
				Payload: raw,
				Proto:   "tcp",
				SrcPort: 12345,
				DstPort: 502,
			}
			if !dpEngine.ShouldInspect(state, pkt) {
				continue
			}
			events, err := dpEngine.DPI().OnPacket(state, pkt)
			if err != nil {
				logger.Printf("mock dpi error: %v", err)
				continue
			}
		dpEngine.RecordDPIEvents(state, pkt, events)
		for _, ev := range events {
			logger.Printf("dpi event proto=%s kind=%s attrs=%v", ev.Proto, ev.Kind, ev.Attributes)
		}
	}
}

func eventsHandler(dpEngine *engine.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit := parseLimit(r, 500)
		list := dpEngine.Events().List(limit)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(list)
	}
}

func flowsHandler(dpEngine *engine.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit := parseLimit(r, 200)
		list := dpEngine.Events().Flows(limit)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(list)
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
