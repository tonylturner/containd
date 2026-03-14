// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cli

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/kballard/go-shellquote"
	"github.com/tonylturner/containd/pkg/cp/config"
)

// Command is a simple handler signature for CLI commands.
type Command func(ctx context.Context, out io.Writer, args []string) error

// Registry holds available commands.
type Registry struct {
	commands map[string]Command
	roles    map[string]Role
}

// NewRegistry initializes the command registry with built-in commands.
func NewRegistry(store config.Store, api *API) *Registry {
	r := &Registry{commands: map[string]Command{}, roles: map[string]Role{}}
	r.RegisterRole("show version", RoleView, showVersion)
	r.RegisterRole("convert sigma", RoleView, convertSigma)
	r.RegisterRole("help", RoleView, helpCommand(r))
	r.RegisterRole("show help", RoleView, showHelpCommand(r))
	r.RegisterRole("set help", RoleView, setHelpCommand(r))
	// Local diagnostics (available in SSH; may require CAP_NET_RAW for some features).
	r.RegisterRole("show ip route", RoleView, showIPRoute())
	r.RegisterRole("show ip rule", RoleView, showIPRule())
	r.RegisterRole("show neighbors", RoleView, showNeighbors())
	r.RegisterRole("show interfaces os", RoleView, showInterfacesOS())
	r.RegisterRole("diag ping", RoleView, diagPing())
	r.RegisterRole("diag traceroute", RoleView, diagTraceroute())
	r.RegisterRole("diag tcptraceroute", RoleView, diagTCPTraceroute())
	r.RegisterRole("diag reach", RoleView, diagReach(store))
	r.RegisterRole("diag capture", RoleAdmin, diagCapture())
	if api != nil {
		r.RegisterRole("show health", RoleView, showHealth(api))
		r.RegisterRole("show config", RoleView, showConfig(api))
		r.RegisterRole("show running-config", RoleView, showRunningConfig(api))
		r.RegisterRole("show running-config redacted", RoleView, showRunningConfigRedacted(api))
		r.RegisterRole("show candidate-config", RoleView, showCandidateConfig(api))
		r.RegisterRole("show diff", RoleView, showDiff(api))
		r.RegisterRole("show auth", RoleView, showAuth(api))
		r.RegisterRole("show system", RoleView, showSystem(api))
		r.RegisterRole("show mgmt listeners", RoleView, showMgmtListeners(api))
		r.RegisterRole("show services", RoleView, showServicesStatus(api))
		r.RegisterRole("show services status", RoleView, showServicesStatus(api))
		r.RegisterRole("show syslog", RoleView, showSyslogConfig(api))
		r.RegisterRole("show syslog config", RoleView, showSyslogConfig(api))
		r.RegisterRole("show syslog status", RoleView, showSyslogStatus(api))
		r.RegisterRole("set syslog format", RoleAdmin, setSyslogFormatAPI(api))
		r.RegisterRole("set syslog forwarder add", RoleAdmin, setSyslogForwarderAddAPI(api))
		r.RegisterRole("set syslog forwarder del", RoleAdmin, setSyslogForwarderDelAPI(api))
		r.RegisterRole("show dhcp", RoleView, showDHCPConfig(api))
		r.RegisterRole("show dhcp config", RoleView, showDHCPConfig(api))
		r.RegisterRole("show dhcp leases", RoleView, showDHCPLeases(api))
		r.RegisterRole("show audit", RoleView, showAudit(api))
		r.RegisterRole("show dataplane", RoleView, showDataPlane(api))
		r.RegisterRole("show proxy forward", RoleView, showForwardProxy(api))
		r.RegisterRole("show proxy reverse", RoleView, showReverseProxy(api))
		r.RegisterRole("show flows", RoleView, showFlows(api))
		r.RegisterRole("show events", RoleView, showEvents(api))
		r.RegisterRole("show stats protocols", RoleView, showStatsProtocols(api))
		r.RegisterRole("show stats top-talkers", RoleView, showStatsTopTalkers(api))
		r.RegisterRole("show anomalies", RoleView, showAnomalies(api))
		r.RegisterRole("show zones", RoleView, showZonesAPI(api))
		r.RegisterRole("show interfaces", RoleView, showInterfacesAPI(api))
		r.RegisterRole("show interfaces state", RoleView, showInterfacesStateAPI(api))
		r.RegisterRole("show routing", RoleView, showRoutingAPI(api))
		r.RegisterRole("show nat", RoleView, showNATAPI(api))
		r.RegisterRole("show port-forwards", RoleView, showPortForwardsAPI(api))
		r.RegisterRole("show portforwards", RoleView, showPortForwardsAPI(api))
		r.RegisterRole("show conntrack", RoleView, showConntrackAPI(api))
		r.RegisterRole("show sessions", RoleView, showConntrackAPI(api))
		r.RegisterRole("analyze pcap", RoleView, analyzePcapAPI(api))
		r.RegisterRole("assign interfaces", RoleAdmin, assignInterfacesAPI(api))
		r.RegisterRole("diag routing reconcile", RoleAdmin, routingReconcileAPI(api))
		r.RegisterRole("show templates", RoleView, showTemplatesAPI(api))
		r.RegisterRole("apply template", RoleAdmin, applyTemplateAPI(api))
		r.RegisterRole("show assets", RoleView, showAssetsAPI(api))
		r.RegisterRole("show inventory", RoleView, showInventoryAPI(api))
		r.RegisterRole("show firewall rules", RoleView, showFirewallRulesAPI(api))
		r.RegisterRole("show ids rules", RoleView, showIDSRulesAPI(api))
		r.RegisterRole("show signatures", RoleView, showSignaturesAPI(api))
		r.RegisterRole("show signature matches", RoleView, showSignatureMatchesAPI(api))
		r.RegisterRole("show learn profiles", RoleView, showLearnProfiles(api))
		r.RegisterRole("show learn rules", RoleView, showLearnRules(api))
		r.RegisterRole("apply learn rules", RoleAdmin, applyLearnRules(api))
		r.RegisterRole("clear learn data", RoleAdmin, clearLearnData(api))
		r.RegisterRole("set zone", RoleAdmin, setZoneAPI(api))
		r.RegisterRole("set interface", RoleAdmin, setInterfaceAPI(api))
		r.RegisterRole("set interface bridge", RoleAdmin, setInterfaceBridgeAPI(api))
		r.RegisterRole("set interface vlan", RoleAdmin, setInterfaceVLANAPI(api))
		r.RegisterRole("set interface bind", RoleAdmin, setInterfaceBindAPI(api))
		r.RegisterRole("set interface zone", RoleAdmin, setInterfaceZoneAPI(api))
		r.RegisterRole("set interface ip", RoleAdmin, setInterfaceIPAPI(api))
		r.RegisterRole("set route add", RoleAdmin, setRouteAddAPI(api))
		r.RegisterRole("set route del", RoleAdmin, setRouteDelAPI(api))
		r.RegisterRole("set ip rule add", RoleAdmin, setIPRuleAddAPI(api))
		r.RegisterRole("set ip rule del", RoleAdmin, setIPRuleDelAPI(api))
		r.RegisterRole("diag interfaces reconcile", RoleAdmin, interfacesReconcileAPI(api))
		r.RegisterRole("set firewall rule", RoleAdmin, setFirewallRuleAPI(api))
		r.RegisterRole("set firewall ics-rule", RoleAdmin, setFirewallICSRuleAPI(api))
		r.RegisterRole("show firewall ics-rules", RoleView, showFirewallICSRulesAPI(api))
		r.RegisterRole("delete firewall rule", RoleAdmin, deleteFirewallRuleAPI(api))
		r.RegisterRole("set nat", RoleAdmin, setNATAPI(api))
		r.RegisterRole("set outbound quickstart", RoleAdmin, setOutboundQuickstartLANWAN(api))
		r.RegisterRole("set port-forward add", RoleAdmin, setPortForwardAddAPI(api))
		r.RegisterRole("set port-forward del", RoleAdmin, setPortForwardDelAPI(api))
		r.RegisterRole("set port-forward enable", RoleAdmin, setPortForwardEnableAPI(api, true))
		r.RegisterRole("set port-forward disable", RoleAdmin, setPortForwardEnableAPI(api, false))
		r.RegisterRole("set dataplane", RoleAdmin, setDataPlaneAPI(api))
		r.RegisterRole("set dataplane block host", RoleAdmin, setDataPlaneBlockHostAPI(api))
		r.RegisterRole("set dataplane block flow", RoleAdmin, setDataPlaneBlockFlowAPI(api))
		r.RegisterRole("set system hostname", RoleAdmin, setSystemHostnameAPI(api))
		r.RegisterRole("set system mgmt listen", RoleAdmin, setSystemMgmtListenAPI(api))
		r.RegisterRole("set system mgmt http listen", RoleAdmin, setSystemMgmtHTTPListenAPI(api))
		r.RegisterRole("set system mgmt https listen", RoleAdmin, setSystemMgmtHTTPSListenAPI(api))
		r.RegisterRole("set system mgmt http enable", RoleAdmin, setSystemMgmtEnableHTTPAPI(api))
		r.RegisterRole("set system mgmt https enable", RoleAdmin, setSystemMgmtEnableHTTPSAPI(api))
		r.RegisterRole("set system mgmt redirect-http-to-https", RoleAdmin, setSystemMgmtRedirectHTTPToHTTPSAPI(api))
		r.RegisterRole("set system mgmt hsts", RoleAdmin, setSystemMgmtHSTSAPI(api))
		r.RegisterRole("set system ssh listen", RoleAdmin, setSystemSSHListenAPI(api))
		r.RegisterRole("set system ssh allow-password", RoleAdmin, setSystemSSHAllowPasswordAPI(api))
		r.RegisterRole("set system ssh authorized-keys-dir", RoleAdmin, setSystemSSHAuthorizedKeysDirAPI(api))
		r.RegisterRole("set system ssh banner", RoleAdmin, setSystemSSHBannerAPI(api))
		r.RegisterRole("set system ssh host-key-rotation", RoleAdmin, setSystemSSHHostKeyRotationAPI(api))
		r.RegisterRole("set proxy forward", RoleAdmin, setForwardProxyAPI(api))
		r.RegisterRole("set proxy reverse", RoleAdmin, setReverseProxyAPI(api))
		r.RegisterRole("factory reset", RoleAdmin, factoryResetAPI(api))
		r.RegisterRole("commit", RoleAdmin, commitAPI(api))
		r.RegisterRole("commit confirmed", RoleAdmin, commitConfirmedAPI(api))
		r.RegisterRole("confirm", RoleAdmin, confirmCommitAPI(api))
		r.RegisterRole("rollback", RoleAdmin, rollbackAPI(api))
		r.RegisterRole("export config", RoleAdmin, exportConfigAPI(api))
		r.RegisterRole("import config", RoleAdmin, importConfigAPI(api))
	} else if store != nil {
		r.RegisterRole("show zones", RoleView, showZones(store))
		r.RegisterRole("show interfaces", RoleView, showInterfaces(store))
	}
	return r
}

// Register adds a command handler.
func (r *Registry) Register(name string, cmd Command) {
	if r.commands == nil {
		r.commands = map[string]Command{}
	}
	r.commands[name] = cmd
	if r.roles == nil {
		r.roles = map[string]Role{}
	}
	// Default to view access unless specified.
	if _, ok := r.roles[name]; !ok {
		r.roles[name] = RoleView
	}
}

// RegisterRole adds a command handler with an explicit minimum role.
func (r *Registry) RegisterRole(name string, role Role, cmd Command) {
	r.Register(name, cmd)
	if r.roles == nil {
		r.roles = map[string]Role{}
	}
	r.roles[name] = role
}

// Execute runs a command by full name.
func (r *Registry) Execute(ctx context.Context, name string, out io.Writer, args []string) error {
	cmd, ok := r.commands[name]
	if !ok {
		return fmt.Errorf("unknown command: %s", name)
	}
	required := RoleView
	if r.roles != nil {
		if v, ok := r.roles[name]; ok && v != "" {
			required = v
		}
	}
	have := roleFromContext(ctx)
	if !allowed(required, have) {
		return fmt.Errorf("%w: %s requires %s", ErrPermissionDenied, name, required)
	}
	return cmd(ctx, out, args)
}

// Commands returns available command names.
func (r *Registry) Commands() []string {
	if r == nil || r.commands == nil {
		return nil
	}
	out := make([]string, 0, len(r.commands))
	for key := range r.commands {
		out = append(out, key)
	}
	return out
}

// CommandsForRole returns commands available to the given role.
func (r *Registry) CommandsForRole(role Role) []string {
	if r == nil || r.commands == nil {
		return nil
	}
	out := make([]string, 0, len(r.commands))
	for name := range r.commands {
		required := RoleView
		if r.roles != nil {
			if v, ok := r.roles[name]; ok && v != "" {
				required = v
			}
		}
		if allowed(required, role) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// ParseAndExecute splits a CLI line (bash-style) and executes it.
// It matches the longest registered command prefix, passing remaining tokens as args.
func (r *Registry) ParseAndExecute(ctx context.Context, line string, out io.Writer) error {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	tokens, err := shellquote.Split(line)
	if err != nil {
		return err
	}
	if len(tokens) == 0 {
		return nil
	}
	name, args := matchCommand(tokens, r.Commands())
	if name == "" {
		return fmt.Errorf("unknown command: %s", tokens[0])
	}
	return r.Execute(ctx, name, out, args)
}

func matchCommand(tokens []string, available []string) (string, []string) {
	if len(tokens) == 0 {
		return "", nil
	}
	availableSet := map[string]struct{}{}
	for _, command := range available {
		availableSet[command] = struct{}{}
	}
	for i := len(tokens); i > 0; i-- {
		candidate := strings.ToLower(strings.Join(tokens[:i], " "))
		if _, ok := availableSet[candidate]; ok {
			return candidate, tokens[i:]
		}
	}
	return "", nil
}
