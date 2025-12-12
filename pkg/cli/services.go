package cli

import (
	"context"
	"fmt"
	"io"
	"sort"
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
		detail := ""
		if fwds != "" {
			detail = "forwarders=" + fwds
		}
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

	// Any other services: list keys for now.
	var extras []string
	for k := range payload {
		if k == "syslog" || k == "proxy" {
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
