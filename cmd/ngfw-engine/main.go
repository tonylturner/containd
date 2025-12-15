package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/containd/containd/pkg/common/logging"
	"github.com/containd/containd/pkg/cp/config"
	"github.com/containd/containd/pkg/dp/capture"
	"github.com/containd/containd/pkg/dp/conntrack"
	"github.com/containd/containd/pkg/dp/dhcpd"
	"github.com/containd/containd/pkg/dp/dpi"
	"github.com/containd/containd/pkg/dp/enforce"
	"github.com/containd/containd/pkg/dp/engine"
	dpevents "github.com/containd/containd/pkg/dp/events"
	"github.com/containd/containd/pkg/dp/flow"
	"github.com/containd/containd/pkg/dp/netcfg"
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
	ownership := newOwnershipManager(logger)

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

	ownership.start(context.Background())
	dhcpMgr := dhcpd.NewManager()
	// Emit DHCP runtime events into the unified telemetry store.
	if dhcpMgr != nil {
		dhcpMgr.SetOnEvent(func(kind string, attrs map[string]any) {
			if dpEngine == nil || dpEngine.Events() == nil {
				return
			}
			dpEngine.Events().Append(dpevents.Event{
				Proto:      "dhcp",
				Kind:       kind,
				Attributes: attrs,
				Timestamp:  time.Now().UTC(),
			})
		})
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/internal/apply_rules", applyRulesHandler(dpEngine))
	mux.HandleFunc("/internal/rules", getRulesHandler(dpEngine))
	mux.HandleFunc("/internal/config", configHandler(logger, dpEngine))
	mux.HandleFunc("/internal/interfaces", interfacesHandler(logger, ownership))
	mux.HandleFunc("/internal/routing", routingHandler(logger, ownership))
	mux.HandleFunc("/internal/interfaces/state", interfacesStateHandler())
	mux.HandleFunc("/internal/ownership", ownershipHandler(ownership))
	mux.HandleFunc("/internal/events", eventsHandler(dpEngine))
	mux.HandleFunc("/internal/flows", flowsHandler(dpEngine))
	mux.HandleFunc("/internal/conntrack", conntrackHandler())
	mux.HandleFunc("/internal/services", servicesHandler(logger, dpEngine, ownership, dhcpMgr))
	mux.HandleFunc("/internal/wireguard/status", wireguardStatusHandler())
	mux.HandleFunc("/internal/dhcp/leases", dhcpLeasesHandler(dhcpMgr))

	logger.Printf("ngfw-engine starting on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		logger.Fatalf("server exited: %v", err)
	}
}

func wireguardStatusHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		iface := strings.TrimSpace(r.URL.Query().Get("iface"))
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		st, err := netcfg.GetWireGuardStatus(ctx, iface)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "not supported") {
				http.Error(w, err.Error(), http.StatusNotImplemented)
				return
			}
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(st)
	}
}

func servicesHandler(logger *log.Logger, dpEngine *engine.Engine, ownership *ownershipManager, dhcpMgr *dhcpd.Manager) http.HandlerFunc {
	var current config.ServicesConfig
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
			var svc config.ServicesConfig
			if err := json.Unmarshal(body, &svc); err != nil {
				http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			// WireGuard runs in the engine (privileged) because it requires NET_ADMIN.
			if err := netcfg.ApplyWireGuard(ctx, svc.VPN.WireGuard); err != nil {
				logger.Printf("apply wireguard failed: %v", err)
				if dpEngine != nil && dpEngine.Events() != nil {
					dpEngine.Events().Append(dpevents.Event{
						Proto:     "vpn",
						Kind:      "service.wireguard.apply_failed",
						Timestamp: time.Now().UTC(),
						Attributes: map[string]any{
							"error": err.Error(),
						},
					})
				}
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if dpEngine != nil && dpEngine.Events() != nil {
				kind := "service.wireguard.disabled"
				if svc.VPN.WireGuard.Enabled {
					kind = "service.wireguard.applied"
				}
				dpEngine.Events().Append(dpevents.Event{
					Proto:     "vpn",
					Kind:      kind,
					Timestamp: time.Now().UTC(),
					Attributes: map[string]any{
						"interface": func() string {
							if v := strings.TrimSpace(svc.VPN.WireGuard.Interface); v != "" {
								return v
							}
							return "wg0"
						}(),
						"listen_port": func() int {
							if svc.VPN.WireGuard.ListenPort > 0 {
								return svc.VPN.WireGuard.ListenPort
							}
							return 51820
						}(),
						"peers": len(svc.VPN.WireGuard.Peers),
					},
				})
			}
			if dhcpMgr != nil {
				var ifaces []config.Interface
				if ownership != nil {
					ifaces = ownership.currentInterfaces()
				}
				if err := dhcpMgr.Apply(ctx, svc.DHCP, ifaces); err != nil {
					logger.Printf("apply dhcp failed: %v", err)
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
			}
			current = svc
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "applied"})
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}
}

func dhcpLeasesHandler(mgr *dhcpd.Manager) http.HandlerFunc {
	type resp struct {
		Leases []dhcpd.Lease `json:"leases"`
		Status any           `json:"status,omitempty"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if mgr == nil {
			_ = json.NewEncoder(w).Encode(resp{Leases: nil, Status: map[string]any{"enabled": false}})
			return
		}
		_ = json.NewEncoder(w).Encode(resp{Leases: mgr.Leases(), Status: mgr.Status()})
	}
}

func addrFromEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func conntrackHandler() http.HandlerFunc {
	type resp struct {
		Entries []conntrack.Entry `json:"entries"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			limit := 200
			if q := strings.TrimSpace(r.URL.Query().Get("limit")); q != "" {
				if v, err := strconv.Atoi(q); err == nil && v > 0 && v <= 5000 {
					limit = v
				}
			}
			entries, err := conntrack.List(limit)
			if err != nil {
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp{Entries: entries})
			return
		case http.MethodPost:
			var req conntrack.DeleteRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid JSON", http.StatusBadRequest)
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			defer cancel()
			if err := conntrack.Delete(ctx, req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "deleted"})
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	}
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

func interfacesHandler(logger *log.Logger, ownership *ownershipManager) http.HandlerFunc {
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
				logger.Printf("apply interfaces(replace) failed: %v", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		} else {
			if err := netcfg.ApplyInterfaces(ctx, ifaces); err != nil {
				logger.Printf("apply interfaces failed: %v", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		// Store desired state for background ownership reconcile (non-destructive).
		if ownership != nil {
			ownership.setInterfaces(ifaces)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "applied"})
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
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}
}

func routingHandler(logger *log.Logger, ownership *ownershipManager) http.HandlerFunc {
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
			// Best-effort resolve logical iface names (wan/dmz/lanX) to kernel device names
			// using the last known interface bindings.
			// If no bindings exist, the route will still apply when Iface already names a kernel device.
			resolved = resolveRoutingIfaces(routing, ownership.currentInterfaces())
		}
		applyErr := error(nil)
		if strings.EqualFold(mode, "replace") {
			applyErr = netcfg.ApplyRoutingReplace(ctx, resolved)
		} else {
			applyErr = netcfg.ApplyRouting(ctx, resolved)
		}
		if applyErr != nil {
			err := applyErr
			logger.Printf("apply routing failed: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if ownership != nil {
			ownership.setRouting(routing)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "applied"})
	}
}

func ownershipHandler(ownership *ownershipManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(ownershipStatusJSON(ownership))
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
