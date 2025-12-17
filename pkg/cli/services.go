package cli

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

func showServicesStatus(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var payload map[string]any
		if err := api.getJSON(ctx, "/api/v1/services/status", &payload); err != nil {
			return err
		}
		if out == nil {
			return nil
		}
		if status, ok := payload["status"].(string); ok && (status == "unavailable" || status == "unknown") {
			fmt.Fprintf(out, "services status: %s\n", status)
			return nil
		}
		return renderServicesTable(out, payload)
	}
}

// setSyslogFormatAPI updates the syslog format (rfc5424|json).
func setSyslogFormatAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("usage: set syslog format <rfc5424|json>")
		}
		format := strings.ToLower(strings.TrimSpace(args[0]))
		if format != "rfc5424" && format != "json" {
			return fmt.Errorf("invalid format: %s", format)
		}
		payload := map[string]any{"format": format}
		return api.patchJSON(ctx, "/api/v1/services/syslog", payload, out)
	}
}

// setSyslogForwarderAddAPI appends a syslog forwarder.
func setSyslogForwarderAddAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		// usage: set syslog forwarder add <address> <port> [proto]
		if len(args) < 2 {
			return fmt.Errorf("usage: set syslog forwarder add <address> <port> [proto]")
		}
		addr := strings.TrimSpace(args[0])
		if addr == "" {
			return fmt.Errorf("address required")
		}
		portStr := strings.TrimSpace(args[1])
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("invalid port: %s", portStr)
		}
		proto := "udp"
		if len(args) >= 3 {
			proto = strings.ToLower(strings.TrimSpace(args[2]))
		}
		if proto != "udp" && proto != "tcp" && proto != "" {
			return fmt.Errorf("invalid proto: %s (must be udp or tcp)", proto)
		}
		payload := map[string]any{
			"action": "add",
			"forwarder": map[string]any{
				"address": addr,
				"port":    port,
				"proto":   proto,
			},
		}
		return api.patchJSON(ctx, "/api/v1/services/syslog", payload, out)
	}
}

// setSyslogForwarderDelAPI removes a syslog forwarder by address/port.
func setSyslogForwarderDelAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		// usage: set syslog forwarder del <address> <port>
		if len(args) < 2 {
			return fmt.Errorf("usage: set syslog forwarder del <address> <port>")
		}
		addr := strings.TrimSpace(args[0])
		portStr := strings.TrimSpace(args[1])
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("invalid port: %s", portStr)
		}
		if addr == "" {
			return fmt.Errorf("address required")
		}
		payload := map[string]any{
			"action": "del",
			"forwarder": map[string]any{
				"address": addr,
				"port":    port,
			},
		}
		return api.patchJSON(ctx, "/api/v1/services/syslog", payload, out)
	}
}

func renderServicesTable(out io.Writer, payload map[string]any) error {
	type row struct {
		Name    string
		Enabled string
		State   string
		Detail  string
	}
	var rows []row

	// Syslog
	if syslog, ok := payload["syslog"].(map[string]any); ok {
		fwds := fmtAny(syslog["configured_forwarders"])
		format := fmtAny(syslog["format"])
		protos := fmtAny(syslog["protos"])
		var details []string
		if fwds != "" {
			details = append(details, "forwarders="+fwds)
		}
		if format != "" {
			details = append(details, "format="+format)
		}
		if protos != "" {
			details = append(details, "proto="+protos)
		}
		detail := strings.Join(details, " ")
		rows = append(rows, row{Name: "syslog", Enabled: yesNo(fwds != "0"), State: "configured", Detail: detail})
	}

	// Proxy (envoy/nginx)
	if proxy, ok := payload["proxy"].(map[string]any); ok {
		fEnabled := boolAny(proxy["forward_enabled"])
		fRunning := boolAny(proxy["envoy_running"])
		rows = append(rows, row{
			Name:    "envoy-forward",
			Enabled: yesNo(fEnabled),
			State:   runState(fEnabled, fRunning),
			Detail:  pathDetail(proxy["envoy_path"]),
		})
		rEnabled := boolAny(proxy["reverse_enabled"])
		rRunning := boolAny(proxy["nginx_running"])
		rows = append(rows, row{
			Name:    "nginx-reverse",
			Enabled: yesNo(rEnabled),
			State:   runState(rEnabled, rRunning),
			Detail:  pathDetail(proxy["nginx_path"]),
		})
	}

	// DNS (unbound)
	if dns, ok := payload["dns"].(map[string]any); ok {
		enabled := boolAny(dns["enabled"])
		upstreams := fmtAny(dns["configured_upstreams"])
		port := fmtAny(dns["listen_port"])
		detail := ""
		if port != "" {
			detail = "port=" + port
		}
		if upstreams != "" {
			if detail != "" {
				detail += " "
			}
			detail += "upstreams=" + upstreams
		}
		rows = append(rows, row{Name: "dns", Enabled: yesNo(enabled), State: runState(enabled, enabled), Detail: detail})
	}

	// NTP (openntpd)
	if ntp, ok := payload["ntp"].(map[string]any); ok {
		enabled := boolAny(ntp["enabled"])
		servers := fmtAny(ntp["servers_count"])
		detail := ""
		if servers != "" {
			detail = "servers=" + servers
		}
		rows = append(rows, row{Name: "ntp", Enabled: yesNo(enabled), State: runState(enabled, enabled), Detail: detail})
	}

	// Any other services: list keys for now.
	var extras []string
	for k := range payload {
		if k == "syslog" || k == "proxy" || k == "dns" || k == "ntp" {
			continue
		}
		extras = append(extras, k)
	}
	sort.Strings(extras)
	for _, k := range extras {
		rows = append(rows, row{Name: k, Enabled: "?", State: "present", Detail: ""})
	}

	// Render fixed-width table.
	fmt.Fprintln(out, "SERVICE         ENABLED  STATE       DETAIL")
	for _, r := range rows {
		fmt.Fprintf(out, "%-14s %-7s %-11s %s\n", r.Name, r.Enabled, r.State, r.Detail)
	}
	return nil
}

// showSyslogConfig fetches and prints the syslog forwarding configuration.
func showSyslogConfig(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var cfg map[string]any
		if err := api.getJSON(ctx, "/api/v1/services/syslog", &cfg); err != nil {
			return err
		}
		if out == nil {
			return nil
		}
		fmt.Fprintln(out, "Syslog configuration")
		if fmtAny(cfg["format"]) != "" {
			fmt.Fprintf(out, "  format: %s\n", fmtAny(cfg["format"]))
		}
		if fwds, ok := cfg["forwarders"].([]any); ok {
			if len(fwds) == 0 {
				fmt.Fprintln(out, "  forwarders: (none)")
			} else {
				fmt.Fprintln(out, "  forwarders:")
				for i, raw := range fwds {
					if fwd, ok := raw.(map[string]any); ok {
						addr := fmtAny(fwd["address"])
						port := fmtAny(fwd["port"])
						proto := fmtAny(fwd["proto"])
						if proto == "" {
							proto = "udp"
						}
						fmt.Fprintf(out, "    %d) %s:%s proto=%s\n", i+1, addr, port, proto)
					}
				}
			}
		}
		return nil
	}
}

// showSyslogStatus prints the syslog runtime status (forwarders + counters).
func showSyslogStatus(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var payload map[string]any
		if err := api.getJSON(ctx, "/api/v1/services/status", &payload); err != nil {
			return err
		}
		syslog, ok := payload["syslog"].(map[string]any)
		if !ok {
			return fmt.Errorf("syslog status unavailable")
		}
		if out == nil {
			return nil
		}
		fmt.Fprintln(out, "Syslog status")
		fmt.Fprintf(out, "  forwarders: %s\n", fmtAny(syslog["configured_forwarders"]))
		fmt.Fprintf(out, "  format: %s\n", fmtAny(syslog["format"]))
		if p := fmtAny(syslog["protos"]); p != "" {
			fmt.Fprintf(out, "  protos: %s\n", p)
		}
		if s := fmtAny(syslog["sent_total"]); s != "" {
			fmt.Fprintf(out, "  sent_total: %s\n", s)
		}
		if f := fmtAny(syslog["failed_total"]); f != "" {
			fmt.Fprintf(out, "  failed_total: %s\n", f)
		}
		if lb := fmtAny(syslog["last_batch"]); lb != "" {
			fmt.Fprintf(out, "  last_batch: %s (limit %s)\n", lb, fmtAny(syslog["batch_limit"]))
		}
		if lf := fmtAny(syslog["last_flush"]); lf != "" {
			fmt.Fprintf(out, "  last_flush: %s\n", lf)
		}
		if le := fmtAny(syslog["last_error"]); le != "" {
			fmt.Fprintf(out, "  last_error: %s\n", le)
		}
		return nil
	}
}

// showDHCPConfig prints the DHCP service configuration, including reservations.
func showDHCPConfig(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var cfg map[string]any
		if err := api.getJSON(ctx, "/api/v1/services/dhcp", &cfg); err != nil {
			return err
		}
		if out == nil {
			return nil
		}
		fmt.Fprintln(out, "DHCP configuration")
		fmt.Fprintf(out, "  enabled: %v\n", boolAny(cfg["enabled"]))
		if li := fmtAny(cfg["listenIfaces"]); li != "" {
			fmt.Fprintf(out, "  listenIfaces: %s\n", li)
		}
		if pools, ok := cfg["pools"].([]any); ok {
			fmt.Fprintf(out, "  pools (%d):\n", len(pools))
			for i, raw := range pools {
				if p, ok := raw.(map[string]any); ok {
					fmt.Fprintf(out, "    %d) %s %s-%s\n", i+1, fmtAny(p["iface"]), fmtAny(p["start"]), fmtAny(p["end"]))
				}
			}
		}
		if res, ok := cfg["reservations"].([]any); ok {
			fmt.Fprintf(out, "  reservations (%d):\n", len(res))
			for i, raw := range res {
				if r, ok := raw.(map[string]any); ok {
					fmt.Fprintf(out, "    %d) %s %s -> %s\n", i+1, fmtAny(r["iface"]), strings.ToLower(fmtAny(r["mac"])), fmtAny(r["ip"]))
				}
			}
		}
		return nil
	}
}

// showDHCPLeases lists active leases.
func showDHCPLeases(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var resp struct {
			Leases []map[string]any `json:"leases"`
		}
		if err := api.getJSON(ctx, "/api/v1/dhcp/leases", &resp); err != nil {
			return err
		}
		if out == nil {
			return nil
		}
		if len(resp.Leases) == 0 {
			fmt.Fprintln(out, "No leases.")
			return nil
		}
		fmt.Fprintln(out, "IFACE  MAC                IP              EXPIRES                HOSTNAME")
		for _, l := range resp.Leases {
			fmt.Fprintf(out, "%-6s %-18s %-15s %-21s %s\n",
				fmtAny(l["iface"]),
				fmtAny(l["mac"]),
				fmtAny(l["ip"]),
				fmtAny(l["expiresAt"]),
				fmtAny(l["hostname"]),
			)
		}
		return nil
	}
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func runState(enabled, running bool) string {
	if !enabled {
		return "stopped"
	}
	if running {
		return "running"
	}
	return "starting"
}

func boolAny(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t == "1" || strings.EqualFold(t, "true") || strings.EqualFold(t, "yes")
	default:
		return false
	}
}

func fmtAny(v any) string {
	switch t := v.(type) {
	case int:
		return fmt.Sprintf("%d", t)
	case int64:
		return fmt.Sprintf("%d", t)
	case float64:
		return fmt.Sprintf("%.0f", t)
	case string:
		return t
	default:
		return ""
	}
}

func pathDetail(v any) string {
	if s, ok := v.(string); ok && s != "" {
		return "path=" + s
	}
	return ""
}
