// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cli

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/audit"
	"github.com/tonylturner/containd/pkg/cp/config"
	dpevents "github.com/tonylturner/containd/pkg/dp/events"
)

func showVersion(ctx context.Context, out io.Writer, args []string) error {
	_, err := fmt.Fprintf(out, "containd %s (%s)\n", config.BuildVersion, config.BuildCommit)
	return err
}

func showHealth(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var payload map[string]any
		if err := api.getJSON(ctx, "/api/v1/health", &payload); err != nil {
			return err
		}
		kv := map[string]string{}
		for k, v := range payload {
			if k == "evidence" {
				if evidence, ok := v.(map[string]any); ok {
					kv["evidence.state"] = firstNonEmpty(fmtAny(evidence["state"]), "unknown")
				} else {
					kv["evidence.state"] = "unknown"
				}
				continue
			}
			kv[k] = fmtAny(v)
		}
		kvTable(out, kv)
		return nil
	}
}

func showConfig(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var cfg config.Config
		if err := api.getJSON(ctx, "/api/v1/config", &cfg); err != nil {
			return err
		}
		return printJSON(out, cfg)
	}
}

func showAuth(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var payload map[string]any
		if err := api.getJSON(ctx, "/api/v1/auth/session", &payload); err != nil {
			return err
		}
		kv := map[string]string{}
		for k, v := range payload {
			switch k {
			case "user":
				continue
			default:
				kv[k] = fmtAny(v)
			}
		}
		if u, ok := payload["user"].(map[string]any); ok {
			if v, ok := u["username"]; ok {
				kv["username"] = fmtAny(v)
			}
			if v, ok := u["role"]; ok {
				kv["user.role"] = fmtAny(v)
			}
			if v, ok := u["id"]; ok {
				kv["user.id"] = fmtAny(v)
			}
		}
		kvTable(out, kv)
		return nil
	}
}

func showAudit(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) == 1 && args[0] == "--status" {
			return showEvidenceStatus(api)(ctx, out, nil)
		}
		if len(args) != 0 {
			return fmt.Errorf("usage: show audit [--status]")
		}
		var records []audit.Record
		if err := api.getJSON(ctx, "/api/v1/audit", &records); err != nil {
			return err
		}
		if out == nil {
			return nil
		}
		if len(records) == 0 {
			fmt.Fprintln(out, "No audit records.")
			return nil
		}
		t := newTable("ID", "TIME", "ACTOR", "SOURCE", "ACTION", "TARGET", "RESULT", "DETAIL")
		for _, r := range records {
			t.addRow(
				fmt.Sprintf("%d", r.ID),
				fmtTime(r.Timestamp),
				truncate(r.Actor, 20),
				truncate(r.Source, 10),
				truncate(r.Action, 24),
				truncate(r.Target, 20),
				truncate(r.Result, 8),
				truncate(r.Detail, 40),
			)
		}
		t.render(out)
		return nil
	}
}

func showDataPlane(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var dp config.DataPlaneConfig
		if err := api.getJSON(ctx, "/api/v1/dataplane", &dp); err != nil {
			return err
		}
		kvTable(out, map[string]string{
			"captureInterfaces": joinCSV(dp.CaptureInterfaces),
			"enforcement":       yesNoStr(dp.Enforcement),
			"enforceTable":      firstNonEmpty(dp.EnforceTable, "containd"),
			"dpiMock":           yesNoStr(dp.DPIMock),
		})
		return nil
	}
}

func showForwardProxy(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var fp config.ForwardProxyConfig
		if err := api.getJSON(ctx, "/api/v1/services/proxy/forward", &fp); err != nil {
			return err
		}
		kvTable(out, map[string]string{
			"enabled":        yesNoStr(fp.Enabled),
			"listenPort":     fmtAny(fp.ListenPort),
			"listenZones":    joinCSV(fp.ListenZones),
			"allowedClients": joinCSV(fp.AllowedClients),
			"allowedDomains": joinCSV(fp.AllowedDomains),
			"upstream":       firstNonEmpty(fp.Upstream, "—"),
			"logRequests":    yesNoStr(fp.LogRequests),
		})
		return nil
	}
}

func showReverseProxy(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var rp config.ReverseProxyConfig
		if err := api.getJSON(ctx, "/api/v1/services/proxy/reverse", &rp); err != nil {
			return err
		}
		if out == nil {
			return nil
		}
		kvTable(out, map[string]string{
			"enabled": yesNoStr(rp.Enabled),
			"sites":   fmt.Sprintf("%d", len(rp.Sites)),
		})
		if len(rp.Sites) > 0 {
			t := newTable("NAME", "PORT", "HOSTNAMES", "BACKENDS", "TLS")
			for _, s := range rp.Sites {
				t.addRow(
					s.Name,
					fmt.Sprintf("%d", s.ListenPort),
					truncate(joinCSV(s.Hostnames), 40),
					truncate(joinCSV(s.Backends), 40),
					yesNoStr(s.TLSEnabled),
				)
			}
			fmt.Fprintln(out)
			t.render(out)
		}
		return nil
	}
}

func showFlows(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var flows []dpevents.FlowSummary
		if err := api.getJSON(ctx, "/api/v1/flows", &flows); err != nil {
			return monitoringUnavailable(out, "Flows", err)
		}
		if out == nil {
			return nil
		}
		if len(flows) == 0 {
			fmt.Fprintln(out, "No flows.")
			return nil
		}
		t := newTable("FLOW", "SRC", "DST", "TRANSPORT", "APP", "FIRST", "LAST", "EVENTS")
		for _, f := range flows {
			src := fmt.Sprintf("%s:%d", f.SrcIP, f.SrcPort)
			dst := fmt.Sprintf("%s:%d", f.DstIP, f.DstPort)
			t.addRow(
				truncate(f.FlowID, 12),
				truncate(src, 22),
				truncate(dst, 22),
				firstNonEmpty(f.Transport, "—"),
				firstNonEmpty(f.Application, "—"),
				fmtTime(f.FirstSeen),
				fmtTime(f.LastSeen),
				fmt.Sprintf("%d", f.EventCount),
			)
		}
		t.render(out)
		return nil
	}
}

func showZones(store config.Store) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		cfg, err := store.Load(ctx)
		if err != nil {
			return err
		}
		if len(cfg.Zones) == 0 {
			_, err = fmt.Fprintln(out, "No zones configured")
			return err
		}
		t := newTable("NAME", "DESCRIPTION")
		for _, z := range cfg.Zones {
			t.addRow(z.Name, firstNonEmpty(z.Description, "—"))
		}
		t.render(out)
		return nil
	}
}

func interfaceMode(iface config.Interface) string {
	if iface.AddressMode != "" {
		return iface.AddressMode
	}
	if len(iface.Addresses) > 0 {
		return "static"
	}
	return "external"
}

func showInterfaces(store config.Store) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		cfg, err := store.Load(ctx)
		if err != nil {
			return err
		}
		if len(cfg.Interfaces) == 0 {
			_, err = fmt.Fprintln(out, "No interfaces configured")
			return err
		}
		t := newTable("NAME", "DEVICE", "ZONE", "MODE", "CONFIG_ADDRS", "GATEWAY", "OS_ADDRS")
		for _, iface := range cfg.Interfaces {
			effectiveDev := firstNonEmpty(iface.Device, iface.Name)
			dev := firstNonEmpty(iface.Device, "—")
			mode := interfaceMode(iface)
			osAddrs := "—"
			if effectiveDev != "" {
				if a, err := osInterfaceAddrs(effectiveDev); err == nil && len(a) > 0 {
					osAddrs = strings.Join(a, ",")
				}
			}
			t.addRow(
				iface.Name,
				dev,
				firstNonEmpty(iface.Zone, "—"),
				mode,
				joinCSV(iface.Addresses),
				firstNonEmpty(iface.Gateway, "—"),
				osAddrs,
			)
		}
		t.render(out)
		if allInterfaceAddrsEmpty(cfg.Interfaces) {
			fmt.Fprintln(out)
			fmt.Fprintln(out, "Note: CONFIG_ADDRS are configured. OS_ADDRS come from the bound kernel interface (DEVICE).")
		}
		return nil
	}
}

func showZonesAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var zones []config.Zone
		if err := api.getJSON(ctx, "/api/v1/zones", &zones); err != nil {
			return err
		}
		if out == nil {
			return nil
		}
		if len(zones) == 0 {
			fmt.Fprintln(out, "No zones configured")
			return nil
		}
		t := newTable("NAME", "DESCRIPTION")
		for _, z := range zones {
			t.addRow(z.Name, firstNonEmpty(z.Description, "—"))
		}
		t.render(out)
		return nil
	}
}

func showInterfacesAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var ifaces []config.Interface
		if err := api.getJSON(ctx, "/api/v1/interfaces", &ifaces); err != nil {
			return err
		}
		var state []config.InterfaceState
		stateErr := api.getJSON(ctx, "/api/v1/interfaces/state", &state)
		if stateErr != nil {
			return monitoringUnavailable(out, "Interface runtime state", stateErr)
		}
		stateByName := map[string]config.InterfaceState{}
		for _, st := range state {
			stateByName[st.Name] = st
		}
		if out == nil {
			return nil
		}
		if len(ifaces) == 0 {
			fmt.Fprintln(out, "No interfaces configured")
			return nil
		}
		t := newTable("NAME", "DEVICE", "ZONE", "MODE", "CONFIG_ADDRS", "GATEWAY", "OS_ADDRS")
		for _, iface := range ifaces {
			effectiveDev := firstNonEmpty(iface.Device, iface.Name)
			dev := firstNonEmpty(iface.Device, "—")
			mode := interfaceMode(iface)
			osAddrs := "—"
			if effectiveDev != "" {
				if st, ok := stateByName[effectiveDev]; ok && len(st.Addrs) > 0 {
					osAddrs = strings.Join(st.Addrs, ",")
				}
			}
			t.addRow(
				iface.Name,
				dev,
				firstNonEmpty(iface.Zone, "—"),
				mode,
				joinCSV(iface.Addresses),
				firstNonEmpty(iface.Gateway, "—"),
				osAddrs,
			)
		}
		t.render(out)
		if allInterfaceAddrsEmpty(ifaces) {
			fmt.Fprintln(out)
			fmt.Fprintln(out, "Note: CONFIG_ADDRS are configured. OS_ADDRS come from the bound kernel interface (DEVICE).")
		}
		return nil
	}
}

func showInterfacesStateAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var state []config.InterfaceState
		if err := api.getJSON(ctx, "/api/v1/interfaces/state", &state); err != nil {
			return monitoringUnavailable(out, "Interface runtime state", err)
		}
		if out == nil {
			return nil
		}
		if len(state) == 0 {
			fmt.Fprintln(out, "No interface state available")
			return nil
		}
		t := newTable("NAME", "INDEX", "UP", "MTU", "MAC", "ADDRS")
		for _, st := range state {
			t.addRow(
				st.Name,
				fmt.Sprintf("%d", st.Index),
				yesNoStr(st.Up),
				fmt.Sprintf("%d", st.MTU),
				firstNonEmpty(st.MAC, "—"),
				truncate(strings.Join(st.Addrs, ","), 64),
			)
		}
		t.render(out)
		return nil
	}
}

func allInterfaceAddrsEmpty(ifaces []config.Interface) bool {
	for _, iface := range ifaces {
		if len(iface.Addresses) > 0 {
			return false
		}
	}
	return true
}

func showAssetsAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var assets []config.Asset
		if err := api.getJSON(ctx, "/api/v1/assets", &assets); err != nil {
			return err
		}
		t := newTable("ID", "NAME", "TYPE", "ZONE", "IPS", "HOSTNAMES", "CRIT", "TAGS")
		for _, a := range assets {
			t.addRow(
				a.ID,
				a.Name,
				string(a.Type),
				firstNonEmpty(a.Zone, "—"),
				joinCSV(a.IPs),
				joinCSV(a.Hostnames),
				firstNonEmpty(string(a.Criticality), "—"),
				joinCSV(a.Tags),
			)
		}
		t.render(out)
		return nil
	}
}

func showFirewallRulesAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		var rules []config.Rule
		if err := api.getJSON(ctx, "/api/v1/firewall/rules", &rules); err != nil {
			return err
		}
		t := newTable("ORDER", "ID", "ACTION", "SRC_ZONES", "DST_ZONES", "SRC", "DST", "PROTO", "ICS", "VIA_FORWARDS")
		for i, r := range rules {
			protos := make([]string, 0, len(r.Protocols))
			for _, p := range r.Protocols {
				if strings.TrimSpace(p.Port) != "" {
					protos = append(protos, p.Name+"/"+p.Port)
				} else {
					protos = append(protos, p.Name)
				}
			}
			ics := "—"
			if strings.TrimSpace(r.ICS.Protocol) != "" {
				ics = r.ICS.Protocol
			}
			t.addRow(
				fmt.Sprint(i+1),
				r.ID,
				string(r.Action),
				joinCSV(r.SourceZones),
				joinCSV(r.DestZones),
				joinCSV(r.Sources),
				joinCSV(r.Destinations),
				joinCSV(protos),
				ics, joinCSV(r.ViaForwards),
			)
		}
		t.render(out)
		return nil
	}
}
