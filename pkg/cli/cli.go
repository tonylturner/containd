// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"encoding/json"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/cp/ids"
)

func assignInterfacesAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("usage: assign interfaces auto | assign interfaces <iface>=<dev> [more...]")
		}
		mode := strings.ToLower(strings.TrimSpace(args[0]))
		req := map[string]any{}
		switch mode {
		case "auto":
			req["mode"] = "auto"
		default:
			mappings := map[string]string{}
			for _, a := range args {
				parts := strings.SplitN(a, "=", 2)
				if len(parts) != 2 {
					return fmt.Errorf("usage: assign interfaces auto | assign interfaces <iface>=<dev> [more...]")
				}
				iface := strings.TrimSpace(parts[0])
				dev := strings.TrimSpace(parts[1])
				if iface == "" {
					continue
				}
				if dev == "" || strings.EqualFold(dev, "none") || dev == "-" {
					dev = ""
				}
				mappings[iface] = dev
			}
			if len(mappings) == 0 {
				return fmt.Errorf("usage: assign interfaces auto | assign interfaces <iface>=<dev> [more...]")
			}
			req["mode"] = "explicit"
			req["mappings"] = mappings
		}

		var payload struct {
			Interfaces []config.Interface `json:"interfaces"`
		}
		if err := api.mutateJSON(ctx, "POST", "/api/v1/interfaces/assign", req, &payload, nil); err != nil {
			return err
		}

		if out == nil {
			return nil
		}
		fmt.Fprintln(out, stagedMessage)
		if len(payload.Interfaces) > 0 {
			fmt.Fprintln(out)
			t := newTable("NAME", "DEVICE", "ZONE", "CONFIG_ADDRS")
			for _, iface := range payload.Interfaces {
				t.addRow(iface.Name, firstNonEmpty(iface.Device, "—"), firstNonEmpty(iface.Zone, "—"), joinCSV(iface.Addresses))
			}
			t.render(out)
		}
		return nil
	}
}

func factoryResetAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) != 1 || strings.TrimSpace(args[0]) != "NUCLEAR" {
			return fmt.Errorf("usage: factory reset NUCLEAR")
		}
		payload := map[string]string{"confirm": "NUCLEAR"}
		return api.postJSON(ctx, "/api/v1/system/factory-reset", payload, out)
	}
}

func convertSigma(ctx context.Context, out io.Writer, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: convert sigma <sigma.yml> [more.yml...]")
	}
	return ids.WriteConvertedSigma(out, args)
}

func interfacesReconcileAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) != 1 || strings.TrimSpace(args[0]) != "REPLACE" {
			return fmt.Errorf("usage: diag interfaces reconcile REPLACE")
		}
		payload := map[string]string{"confirm": "REPLACE"}
		return api.postJSON(ctx, "/api/v1/interfaces/reconcile", payload, out)
	}
}

func setZoneAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("usage: set zone <name> [description]")
		}
		z := config.Zone{Name: args[0]}
		if len(args) > 1 {
			z.Description = args[1]
		}
		return api.postJSON(ctx, "/api/v1/zones", z, out)
	}
}

func setInterfaceAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 2 {
			return fmt.Errorf("usage: set interface <name> <zone> [cidr...]")
		}
		iface := config.Interface{
			Name:      args[0],
			Zone:      args[1],
			Addresses: args[2:],
		}
		return api.postJSON(ctx, "/api/v1/interfaces", iface, out)
	}
}

func setInterfaceBridgeAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 3 {
			return fmt.Errorf("usage: set interface bridge <name> <zone> <members_csv> [cidr...]")
		}
		members := splitCSV(args[2])
		iface := config.Interface{
			Name:      args[0],
			Zone:      args[1],
			Type:      "bridge",
			Members:   members,
			Addresses: args[3:],
		}
		return api.postJSON(ctx, "/api/v1/interfaces", iface, out)
	}
}

func setInterfaceVLANAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 4 {
			return fmt.Errorf("usage: set interface vlan <name> <zone> <parent> <vlan_id> [cidr...]")
		}
		vlanID, err := strconv.Atoi(strings.TrimSpace(args[3]))
		if err != nil {
			return fmt.Errorf("invalid vlan_id %q", args[3])
		}
		iface := config.Interface{
			Name:      args[0],
			Zone:      args[1],
			Type:      "vlan",
			Parent:    args[2],
			VLANID:    vlanID,
			Addresses: args[4:],
		}
		return api.postJSON(ctx, "/api/v1/interfaces", iface, out)
	}
}

func setInterfaceBindAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 2 {
			return fmt.Errorf("usage: set interface bind <name> <os_iface>")
		}
		payload := map[string]any{"device": args[1]}
		return patchExistingInterface(ctx, api, args[0], payload, out)
	}
}

func setInterfaceZoneAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 2 {
			return fmt.Errorf("usage: set interface zone <name> <zone>")
		}
		payload := map[string]any{"zone": args[1]}
		return patchExistingInterface(ctx, api, args[0], payload, out)
	}
}

func setInterfaceIPAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 2 {
			return fmt.Errorf("usage: set interface ip <name> <cidr...|none> | set interface ip <name> static <cidr> [gateway] | set interface ip <name> dhcp")
		}
		ifaceName := args[0]
		mode := strings.ToLower(strings.TrimSpace(args[1]))

		switch mode {
		case "dhcp":
			payload := map[string]any{
				"addressMode": "dhcp",
				"addresses":   []string{},
				"gateway":     "",
			}
			return patchExistingInterface(ctx, api, ifaceName, payload, out)
		case "static":
			if len(args) < 3 {
				return fmt.Errorf("usage: set interface ip %s static <cidr> [gateway]", ifaceName)
			}
			cidr := strings.TrimSpace(args[2])
			gw := ""
			if len(args) >= 4 {
				gw = strings.TrimSpace(args[3])
			}
			payload := map[string]any{
				"addressMode": "static",
				"addresses":   []string{cidr},
				"gateway":     gw,
			}
			return patchExistingInterface(ctx, api, ifaceName, payload, out)
		default:
			addrs := args[1:]
			if len(addrs) == 1 {
				switch strings.ToLower(strings.TrimSpace(addrs[0])) {
				case "none", "clear", "-":
					addrs = []string{}
				}
			}
			payload := map[string]any{
				"addressMode": "static",
				"addresses":   addrs,
				"gateway":     "",
			}
			return patchExistingInterface(ctx, api, ifaceName, payload, out)
		}
	}
}

func deleteFirewallRuleAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("usage: delete firewall rule <id>")
		}
		path := "/api/v1/firewall/rules/" + args[0]
		return api.delete(ctx, path, out)
	}
}

func setDataPlaneAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		// usage: set dataplane enforcement on|off [table] [ifaces...]
		if len(args) < 2 {
			return fmt.Errorf("usage: set dataplane enforcement <on|off> [table] [iface...]")
		}
		if args[0] != "enforcement" {
			return fmt.Errorf("usage: set dataplane enforcement <on|off> [table] [iface...]")
		}
		var on bool
		switch args[1] {
		case "on", "true", "1":
			on = true
		case "off", "false", "0":
			on = false
		default:
			return fmt.Errorf("invalid enforcement value %q: use on, off, true, false, 1, or 0", args[1])
		}

		var dp config.DataPlaneConfig
		revision, err := api.getConfigJSON(ctx, "/api/v1/dataplane", &dp)
		if err != nil {
			return err
		}
		dp.Enforcement = on
		if len(args) > 2 {
			dp.EnforceTable = args[2]
		}
		if len(args) > 3 {
			dp.CaptureInterfaces = args[3:]
		}
		return api.saveJSON(ctx, "/api/v1/dataplane", dp, revision, out)
	}
}

func setDataPlaneBlockHostAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		// usage: set dataplane block host <ip> [ttlSeconds]
		if len(args) < 1 {
			return fmt.Errorf("usage: set dataplane block host <ip> [ttlSeconds]")
		}
		payload := map[string]any{
			"ip": args[0],
		}
		if len(args) > 1 {
			ttl, err := strconv.Atoi(args[1])
			if err != nil || ttl < 0 {
				return fmt.Errorf("invalid ttlSeconds: %s", args[1])
			}
			payload["ttlSeconds"] = ttl
		}
		return api.postJSON(ctx, "/api/v1/dataplane/blocks/host", payload, out)
	}
}

func setDataPlaneBlockFlowAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		// usage: set dataplane block flow <srcIp> <dstIp> <proto> <dstPort> [ttlSeconds]
		if len(args) < 4 {
			return fmt.Errorf("usage: set dataplane block flow <srcIp> <dstIp> <proto> <dstPort> [ttlSeconds]")
		}
		payload := map[string]any{
			"srcIp":   args[0],
			"dstIp":   args[1],
			"proto":   args[2],
			"dstPort": args[3],
		}
		if len(args) > 4 {
			ttl, err := strconv.Atoi(args[4])
			if err != nil || ttl < 0 {
				return fmt.Errorf("invalid ttlSeconds: %s", args[4])
			}
			payload["ttlSeconds"] = ttl
		}
		return api.postJSON(ctx, "/api/v1/dataplane/blocks/flow", payload, out)
	}
}

func setForwardProxyAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		// usage: set proxy forward <on|off> [port] [zone...]
		if len(args) < 1 {
			return fmt.Errorf("usage: set proxy forward <on|off> [port] [zone...]")
		}
		on := args[0] == "on" || args[0] == "true" || args[0] == "1"
		var fp config.ForwardProxyConfig
		revision, err := api.getConfigJSON(ctx, "/api/v1/services/proxy/forward", &fp)
		if err != nil {
			return err
		}
		fp.Enabled = on
		if len(args) > 1 {
			port, err := strconv.Atoi(args[1])
			if err != nil || port <= 0 || port > 65535 {
				return fmt.Errorf("invalid port: %s", args[1])
			}
			fp.ListenPort = port
		}
		if len(args) > 2 {
			fp.ListenZones = args[2:]
		}
		return api.saveJSON(ctx, "/api/v1/services/proxy/forward", fp, revision, out)
	}
}

func setReverseProxyAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		// usage: set proxy reverse <on|off>
		if len(args) < 1 {
			return fmt.Errorf("usage: set proxy reverse <on|off>")
		}
		on := args[0] == "on" || args[0] == "true" || args[0] == "1"
		var rp config.ReverseProxyConfig
		revision, err := api.getConfigJSON(ctx, "/api/v1/services/proxy/reverse", &rp)
		if err != nil {
			return err
		}
		rp.Enabled = on
		return api.saveJSON(ctx, "/api/v1/services/proxy/reverse", rp, revision, out)
	}
}

func commitAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) == 0 {
			return api.postJSON(ctx, "/api/v1/config/commit", map[string]any{}, out)
		}
		if len(args) != 2 || args[0] != "revision" || !config.Revision(args[1]).Valid() {
			return fmt.Errorf("usage: commit [revision <token>]")
		}
		return api.saveJSON(ctx, "/api/v1/config/commit", map[string]any{}, config.Revision(args[1]), out)
	}
}

func commitConfirmedAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		payload := map[string]any{}
		if len(args) > 0 {
			ttl, err := strconv.Atoi(args[0])
			if err != nil || ttl <= 0 {
				return fmt.Errorf("usage: commit confirmed <ttl_seconds>")
			}
			payload["ttl_seconds"] = ttl
		}
		return api.postJSON(ctx, "/api/v1/config/commit_confirmed", payload, out)
	}
}

func confirmCommitAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		return api.postJSON(ctx, "/api/v1/config/confirm", map[string]any{}, out)
	}
}

func rollbackAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		return api.postJSON(ctx, "/api/v1/config/rollback", map[string]any{}, out)
	}
}

func exportConfigAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		redacted := len(args) > 0 && (args[0] == "redacted" || args[0] == "--redacted")
		var cfg config.Config
		path := "/api/v1/config/export"
		if redacted {
			path += "?redacted=1"
		}
		if err := api.getJSON(ctx, path, &cfg); err != nil {
			return err
		}
		return printJSON(out, cfg)
	}
}

func importConfigAPI(api *API) Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("usage: import config <path>")
		}
		raw, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}
		var cfg config.Config
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return fmt.Errorf("invalid JSON: %w", err)
		}
		return api.postJSON(ctx, "/api/v1/config/import", cfg, out)
	}
}

func printJSON(out io.Writer, v any) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
