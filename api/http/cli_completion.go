// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package httpapi

import (
	"sort"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

type cliCompletionContext struct {
	prefix       string
	argIndex     int
	prev         string
	args         []string
	allCommands  []string
	ifaces       []string
	zones        []string
	rules        []string
	portForwards []string
	gateways     []string
}

type cliCompletionFunc func(cliCompletionContext) []string
type cliUsageHintFunc func(cliCompletionContext) []string

var cliCompletionHandlers = map[string]cliCompletionFunc{
	"help":                     completeHelp,
	"show help":                completeShowHelp,
	"set help":                 completeSetHelp,
	"set zone":                 completeSetZone,
	"set interface":            completeSetInterface,
	"set interface ip":         completeSetInterfaceIP,
	"set interface zone":       completeSetInterfaceZone,
	"set interface bind":       completeSetInterfaceBind,
	"set interface bridge":     completeSetInterfaceBridge,
	"set interface vlan":       completeSetInterfaceVLAN,
	"assign interfaces":        completeAssignInterfaces,
	"set firewall rule":        completeSetFirewallRule,
	"delete firewall rule":     completeDeleteFirewallRule,
	"set port-forward add":     completePortForwardAdd,
	"set port-forward del":     completePortForwardID,
	"set port-forward enable":  completePortForwardID,
	"set port-forward disable": completePortForwardID,
	"set dataplane":            completeSetDataplane,
	"set proxy forward":        completeSetProxyForward,
	"set proxy reverse":        completeSetProxyReverse,
	"set nat":                  completeSetNAT,
	"diag reach":               completeDiagReach,
	"diag capture":             completeDiagCapture,
	"set route add":            completeSetRoute,
	"set route del":            completeSetRoute,
	"set ip rule add":          completeSetIPRuleAdd,
	"set ip rule del":          completeSetIPRuleDel,
	"set syslog format":        completeSyslogFormat,
	"set syslog forwarder add": completeSyslogForwarderAdd,
	"set syslog forwarder del": completeSyslogForwarderDel,
}

var cliUsageHintHandlers = map[string]cliUsageHintFunc{
	"convert sigma":                          staticArgHints(0, "<sigma.yml>"),
	"factory reset":                          staticArgHints(0, "NUCLEAR"),
	"commit confirmed":                       staticArgHints(0, "<ttl_seconds>"),
	"import config":                          staticArgHints(0, "<path>"),
	"export config":                          staticArgHints(0, "<path>"),
	"diag ping":                              staticArgHints(0, "<host>", 1, "[count]"),
	"diag traceroute":                        staticArgHints(0, "<host>", 1, "[max_hops]"),
	"diag tcptraceroute":                     staticArgHints(0, "<host>", 1, "<port>", 2, "[max_hops]"),
	"diag reach":                             usageDiagReach,
	"diag capture":                           staticArgHints(0, "<iface>", 1, "[seconds]", 2, "[file]"),
	"diag routing reconcile":                 staticArgHints(0, "REPLACE"),
	"diag interfaces reconcile":              staticArgHints(0, "REPLACE"),
	"set syslog format":                      staticArgHints(0, "rfc5424", "json"),
	"set syslog forwarder add":               staticArgHints(0, "<address>", 1, "<port>", 2, "udp", "tcp"),
	"set syslog forwarder del":               staticArgHints(0, "<address>", 1, "<port>"),
	"set system hostname":                    staticArgHints(0, "<name>"),
	"set system mgmt listen":                 staticArgHints(0, "<addr>"),
	"set system mgmt http listen":            staticArgHints(0, "<addr>"),
	"set system mgmt https listen":           staticArgHints(0, "<addr>"),
	"set system mgmt http enable":            staticArgHints(0, "true", "false"),
	"set system mgmt https enable":           staticArgHints(0, "true", "false"),
	"set system mgmt redirect-http-to-https": staticArgHints(0, "true", "false"),
	"set system mgmt hsts":                   staticArgHints(0, "true", "false", 1, "[max_age_seconds]"),
	"set system ssh listen":                  staticArgHints(0, "<addr>"),
	"set system ssh allow-password":          staticArgHints(0, "true", "false"),
	"set system ssh authorized-keys-dir":     staticArgHints(0, "<dir>"),
	"set interface ip":                       usageSetInterfaceIP,
	"set interface bind":                     staticArgHints(1, "<os_iface>"),
	"set interface bridge":                   staticArgHints(2, "<members_csv>"),
	"set interface vlan":                     staticArgHints(3, "<vlan_id>"),
	"set firewall rule":                      staticArgHints(0, "<id>", 1, "ALLOW", "DENY"),
	"delete firewall rule":                   staticArgHints(0, "<id>"),
	"set port-forward add":                   usagePortForwardAdd,
	"set port-forward del":                   staticArgHints(0, "<id>"),
	"set port-forward enable":                staticArgHints(0, "<id>"),
	"set port-forward disable":               staticArgHints(0, "<id>"),
	"set proxy forward":                      staticArgHints(0, "on", "off", "true", "false", 1, "[port]"),
	"set proxy reverse":                      staticArgHints(0, "on", "off", "true", "false"),
	"set nat":                                usageSetNAT,
	"set dataplane":                          usageSetDataplane,
	"set route add":                          usageSetRoute,
	"set route del":                          usageSetRoute,
	"set ip rule add":                        usageSetIPRuleAdd,
	"set ip rule del":                        usageSetIPRuleDel,
}

func completeCLIArgs(cmd string, args []string, cfg *config.Config, allCommands []string) []string {
	ctx := newCLICompletionContext(args, cfg, allCommands)
	if handler, ok := cliCompletionHandlers[cmd]; ok {
		return filterPrefix(handler(ctx), ctx.prefix)
	}
	if hints := usageHints(cmd, ctx.argIndex, args); len(hints) > 0 {
		return filterPrefix(hints, ctx.prefix)
	}
	return nil
}

func newCLICompletionContext(args []string, cfg *config.Config, allCommands []string) cliCompletionContext {
	prefix := ""
	if len(args) > 0 {
		prefix = args[len(args)-1]
	}
	prev := ""
	if len(args) >= 2 {
		prev = strings.ToLower(strings.TrimSpace(args[len(args)-2]))
	}
	return cliCompletionContext{
		prefix:       prefix,
		argIndex:     len(args) - 1,
		prev:         prev,
		args:         args,
		allCommands:  allCommands,
		ifaces:       interfaceNames(cfg),
		zones:        zoneNames(cfg),
		rules:        firewallRuleIDs(cfg),
		portForwards: portForwardIDs(cfg),
		gateways:     gatewayAddresses(cfg),
	}
}

func completeHelp(ctx cliCompletionContext) []string {
	if ctx.argIndex != 0 {
		return nil
	}
	return ctx.allCommands
}

func completeShowHelp(ctx cliCompletionContext) []string {
	if ctx.argIndex != 0 {
		return nil
	}
	return filterCommandPrefix(ctx.allCommands, "show ")
}

func completeSetHelp(ctx cliCompletionContext) []string {
	if ctx.argIndex != 0 {
		return nil
	}
	return filterCommandPrefix(ctx.allCommands, "set ")
}

func completeSetZone(ctx cliCompletionContext) []string {
	if ctx.argIndex == 0 {
		return ctx.zones
	}
	return nil
}

func completeSetInterface(ctx cliCompletionContext) []string {
	switch {
	case ctx.argIndex == 0:
		return ctx.ifaces
	case ctx.argIndex == 1:
		return ctx.zones
	case ctx.argIndex >= 2:
		return []string{"<cidr...>", "none"}
	default:
		return nil
	}
}

func completeSetInterfaceIP(ctx cliCompletionContext) []string {
	switch {
	case ctx.argIndex == 0:
		return ctx.ifaces
	case ctx.argIndex == 1:
		return []string{"static", "dhcp", "none"}
	case ctx.argIndex >= 2 && len(ctx.args) >= 2 && strings.EqualFold(strings.TrimSpace(ctx.args[1]), "static"):
		return []string{"<cidr>", "[gateway]"}
	default:
		return nil
	}
}

func completeSetInterfaceZone(ctx cliCompletionContext) []string {
	switch ctx.argIndex {
	case 0:
		return ctx.ifaces
	case 1:
		return ctx.zones
	default:
		return nil
	}
}

func completeSetInterfaceBind(ctx cliCompletionContext) []string {
	if ctx.argIndex == 0 {
		return ctx.ifaces
	}
	return nil
}

func completeSetInterfaceBridge(ctx cliCompletionContext) []string {
	switch {
	case ctx.argIndex == 0:
		return ctx.ifaces
	case ctx.argIndex == 1:
		return ctx.zones
	case ctx.argIndex == 2:
		if len(ctx.ifaces) > 0 {
			return ctx.ifaces
		}
		return []string{"<members_csv>"}
	case ctx.argIndex >= 3:
		return []string{"<cidr...>"}
	default:
		return nil
	}
}

func completeSetInterfaceVLAN(ctx cliCompletionContext) []string {
	switch {
	case ctx.argIndex == 0:
		return ctx.ifaces
	case ctx.argIndex == 1:
		return ctx.zones
	case ctx.argIndex == 2:
		return ctx.ifaces
	case ctx.argIndex == 3:
		return []string{"<vlan_id>"}
	case ctx.argIndex >= 4:
		return []string{"<cidr...>"}
	default:
		return nil
	}
}

func completeAssignInterfaces(ctx cliCompletionContext) []string {
	return append([]string{"auto"}, ifaceAssignHints(ctx.ifaces)...)
}

func completeSetFirewallRule(ctx cliCompletionContext) []string {
	switch {
	case ctx.argIndex == 0:
		return ctx.rules
	case ctx.argIndex == 1:
		return []string{"ALLOW", "DENY", "allow", "deny"}
	case ctx.argIndex == 2 || ctx.argIndex == 3:
		return ctx.zones
	default:
		return nil
	}
}

func completeDeleteFirewallRule(ctx cliCompletionContext) []string {
	if ctx.argIndex == 0 {
		return ctx.rules
	}
	return nil
}

func completePortForwardID(ctx cliCompletionContext) []string {
	if ctx.argIndex == 0 {
		return ctx.portForwards
	}
	return nil
}

func completePortForwardAdd(ctx cliCompletionContext) []string {
	switch {
	case ctx.argIndex == 1:
		return ctx.zones
	case ctx.argIndex == 2:
		return []string{"tcp", "udp"}
	case ctx.prev == "sources":
		return []string{"<cidr1,cidr2>"}
	case ctx.prev == "desc":
		return []string{"<text>"}
	default:
		return nil
	}
}

func completeSetDataplane(ctx cliCompletionContext) []string {
	switch {
	case ctx.argIndex == 0:
		return []string{"enforcement"}
	case ctx.argIndex == 1 && strings.EqualFold(strings.TrimSpace(ctx.args[0]), "enforcement"):
		return []string{"on", "off", "true", "false"}
	case ctx.argIndex >= 3 && strings.EqualFold(strings.TrimSpace(ctx.args[0]), "enforcement"):
		return ctx.ifaces
	default:
		return nil
	}
}

func completeSetProxyForward(ctx cliCompletionContext) []string {
	switch {
	case ctx.argIndex == 0:
		return []string{"on", "off", "true", "false"}
	case ctx.argIndex >= 2:
		return ctx.zones
	default:
		return nil
	}
}

func completeSetProxyReverse(ctx cliCompletionContext) []string {
	if ctx.argIndex == 0 {
		return []string{"on", "off", "true", "false"}
	}
	return nil
}

func completeSetNAT(ctx cliCompletionContext) []string {
	switch {
	case ctx.argIndex == 0:
		return []string{"on", "off"}
	case ctx.prev == "egress":
		return withDefaultZoneSuggestions(ctx.zones, "<zone>")
	case ctx.prev == "sources":
		return withDefaultZoneSuggestions(ctx.zones, "<zone1,zone2>")
	default:
		return append([]string{"egress", "sources"}, ctx.zones...)
	}
}

func completeDiagReach(ctx cliCompletionContext) []string {
	switch {
	case ctx.argIndex == 0:
		return ctx.ifaces
	case ctx.argIndex == 2:
		return []string{"tcp", "udp", "icmp"}
	default:
		return nil
	}
}

func completeDiagCapture(ctx cliCompletionContext) []string {
	if ctx.argIndex == 0 {
		return ctx.ifaces
	}
	return nil
}

func completeSetRoute(ctx cliCompletionContext) []string {
	switch {
	case ctx.argIndex == 0:
		return []string{"default", "<dst>"}
	case ctx.prev == "via" || ctx.prev == "gw" || ctx.prev == "gateway":
		if len(ctx.gateways) > 0 {
			return ctx.gateways
		}
		return []string{"<gw>"}
	case ctx.prev == "dev" || ctx.prev == "iface":
		return ctx.ifaces
	default:
		return []string{"via", "dev", "iface", "table", "metric", "gw", "gateway"}
	}
}

func completeSetIPRuleAdd(ctx cliCompletionContext) []string {
	switch ctx.prev {
	case "src", "dst":
		return []string{"<cidr>"}
	case "priority":
		return []string{"<n>"}
	}
	if ctx.argIndex == 0 {
		return []string{"<table>"}
	}
	return []string{"src", "dst", "priority"}
}

func completeSetIPRuleDel(ctx cliCompletionContext) []string {
	switch ctx.prev {
	case "src", "dst":
		return []string{"<cidr>"}
	case "priority":
		return []string{"<n>"}
	}
	if ctx.argIndex == 0 {
		return []string{"<table>"}
	}
	return []string{"src", "dst", "priority", "all"}
}

func completeSyslogFormat(ctx cliCompletionContext) []string {
	if ctx.argIndex == 0 {
		return []string{"rfc5424", "json"}
	}
	return nil
}

func completeSyslogForwarderAdd(ctx cliCompletionContext) []string {
	switch ctx.argIndex {
	case 0:
		return []string{"<address>"}
	case 1:
		return []string{"<port>"}
	case 2:
		return []string{"udp", "tcp"}
	default:
		return nil
	}
}

func completeSyslogForwarderDel(ctx cliCompletionContext) []string {
	switch ctx.argIndex {
	case 0:
		return []string{"<address>"}
	case 1:
		return []string{"<port>"}
	default:
		return nil
	}
}

func usageHints(cmd string, argIndex int, args []string) []string {
	ctx := cliCompletionContext{argIndex: argIndex, args: args}
	if handler, ok := cliUsageHintHandlers[cmd]; ok {
		return handler(ctx)
	}
	return nil
}

func staticArgHints(parts ...any) cliUsageHintFunc {
	indexHints := map[int][]string{}
	currentIndex := 0
	for _, part := range parts {
		switch v := part.(type) {
		case int:
			currentIndex = v
		case string:
			indexHints[currentIndex] = append(indexHints[currentIndex], v)
		default:
			continue
		}
	}
	return func(ctx cliCompletionContext) []string {
		return append([]string(nil), indexHints[ctx.argIndex]...)
	}
}

func usageDiagReach(ctx cliCompletionContext) []string {
	switch ctx.argIndex {
	case 0:
		return []string{"<src_iface>"}
	case 1:
		return []string{"<dst_host|dst_ip|dst_iface>"}
	case 2:
		return []string{"tcp", "udp", "icmp", "[tcp_port]"}
	case 3:
		return []string{"[port]"}
	default:
		return nil
	}
}

func usageSetInterfaceIP(ctx cliCompletionContext) []string {
	if ctx.argIndex == 2 && len(ctx.args) >= 2 && strings.EqualFold(strings.TrimSpace(ctx.args[1]), "static") {
		return []string{"<cidr>", "[gateway]"}
	}
	return nil
}

func usagePortForwardAdd(ctx cliCompletionContext) []string {
	switch ctx.argIndex {
	case 0:
		return []string{"<id>"}
	case 2:
		return []string{"tcp", "udp"}
	case 3:
		return []string{"<listen_port>"}
	case 4:
		return []string{"<dest_ip[:dest_port]>"}
	default:
		if ctx.argIndex >= 5 {
			return []string{"sources", "desc", "off"}
		}
		return nil
	}
}

func usageSetNAT(ctx cliCompletionContext) []string {
	if ctx.argIndex == 0 {
		return []string{"on", "off"}
	}
	if ctx.argIndex >= 1 {
		return []string{"egress", "sources"}
	}
	return nil
}

func usageSetDataplane(ctx cliCompletionContext) []string {
	switch ctx.argIndex {
	case 0:
		return []string{"enforcement"}
	case 1:
		return []string{"on", "off", "true", "false"}
	case 2:
		return []string{"[table]"}
	default:
		return nil
	}
}

func usageSetRoute(ctx cliCompletionContext) []string {
	if ctx.argIndex == 0 {
		return []string{"default"}
	}
	if ctx.argIndex >= 1 {
		return []string{"via", "dev", "iface", "table", "metric", "gw", "gateway"}
	}
	return nil
}

func usageSetIPRuleAdd(ctx cliCompletionContext) []string {
	if ctx.argIndex >= 1 {
		return []string{"src", "dst", "priority"}
	}
	return nil
}

func usageSetIPRuleDel(ctx cliCompletionContext) []string {
	if ctx.argIndex >= 1 {
		return []string{"src", "dst", "priority", "all"}
	}
	return nil
}

func withDefaultZoneSuggestions(zones []string, fallback string) []string {
	if len(zones) > 0 {
		return append([]string{"default"}, zones...)
	}
	return []string{"default", fallback}
}

func filterPrefix(candidates []string, prefix string) []string {
	if len(candidates) == 0 {
		return nil
	}
	needle := strings.ToLower(strings.TrimSpace(prefix))
	seen := map[string]struct{}{}
	out := make([]string, 0, len(candidates))
	for _, cand := range candidates {
		c := strings.TrimSpace(cand)
		if c == "" {
			continue
		}
		if needle != "" && !strings.HasPrefix(strings.ToLower(c), needle) {
			continue
		}
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

func interfaceNames(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	out := make([]string, 0, len(cfg.Interfaces))
	for _, iface := range cfg.Interfaces {
		if strings.TrimSpace(iface.Name) != "" {
			out = append(out, iface.Name)
		}
	}
	return out
}

func zoneNames(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	out := make([]string, 0, len(cfg.Zones))
	for _, z := range cfg.Zones {
		if strings.TrimSpace(z.Name) != "" {
			out = append(out, z.Name)
		}
	}
	return out
}

func firewallRuleIDs(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	out := make([]string, 0, len(cfg.Firewall.Rules))
	for _, r := range cfg.Firewall.Rules {
		if strings.TrimSpace(r.ID) != "" {
			out = append(out, r.ID)
		}
	}
	return out
}

func portForwardIDs(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	out := make([]string, 0, len(cfg.Firewall.NAT.PortForwards))
	for _, pf := range cfg.Firewall.NAT.PortForwards {
		if strings.TrimSpace(pf.ID) != "" {
			out = append(out, pf.ID)
		}
	}
	return out
}

func gatewayAddresses(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	out := make([]string, 0, len(cfg.Routing.Gateways))
	for _, gw := range cfg.Routing.Gateways {
		if strings.TrimSpace(gw.Address) != "" {
			out = append(out, gw.Address)
		}
	}
	return out
}

func ifaceAssignHints(ifaces []string) []string {
	out := make([]string, 0, len(ifaces))
	for _, name := range ifaces {
		if strings.TrimSpace(name) == "" {
			continue
		}
		out = append(out, name+"=")
	}
	return out
}

func filterCommandPrefix(commands []string, prefix string) []string {
	out := make([]string, 0, len(commands))
	for _, cmd := range commands {
		if strings.HasPrefix(cmd, prefix) {
			out = append(out, cmd)
		}
	}
	return out
}
