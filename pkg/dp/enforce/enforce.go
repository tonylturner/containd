package enforce

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/containd/containd/pkg/dp/rules"
)

// Compiler turns a dp rules.Snapshot into an nftables ruleset.
// This is a minimal Phase 1 skeleton.
type Compiler struct {
	TableName string
}

func NewCompiler() *Compiler {
	return &Compiler{TableName: "containd"}
}

// CompileFirewall builds an nftables ruleset for the snapshot's firewall entries.
// Zone/interface bindings and dynamic sets are added in later phases.
func (c *Compiler) CompileFirewall(snap *rules.Snapshot) (string, error) {
	if snap == nil {
		return "", errors.New("snapshot is nil")
	}
	table := c.TableName
	if table == "" {
		table = "containd"
	}

	var buf bytes.Buffer
	buf.WriteString("flush ruleset\n")
	buf.WriteString(fmt.Sprintf("table inet %s {\n", table))
	// Zone interface sets for iifname/oifname binding.
	if len(snap.ZoneIfaces) > 0 {
		zones := make([]string, 0, len(snap.ZoneIfaces))
		for z := range snap.ZoneIfaces {
			zones = append(zones, z)
		}
		sort.Strings(zones)
		for _, z := range zones {
			ifaces := snap.ZoneIfaces[z]
			if len(ifaces) == 0 {
				continue
			}
			setName := "zone_" + sanitizeIdent(z) + "_ifaces"
			buf.WriteString(fmt.Sprintf("  set %s {\n", setName))
			buf.WriteString("    type ifname;\n")
			buf.WriteString("    elements = { ")
			for i, iface := range ifaces {
				if i > 0 {
					buf.WriteString(", ")
				}
				buf.WriteString(fmt.Sprintf("\"%s\"", iface))
			}
			buf.WriteString(" }\n")
			buf.WriteString("  }\n")
		}
	}
	buf.WriteString("  set block_hosts {\n")
	buf.WriteString("    type ipv4_addr;\n")
	buf.WriteString("    flags timeout;\n")
	buf.WriteString("  }\n")
	buf.WriteString("  set block_flows {\n")
	buf.WriteString("    type ipv4_addr . ipv4_addr . inet_service;\n")
	buf.WriteString("    flags timeout;\n")
	buf.WriteString("  }\n")
	// INPUT: traffic destined to the appliance itself.
	// Keep this minimal for now; mgmt/UI runs in a separate container in dev.
	buf.WriteString("  chain input {\n")
	buf.WriteString("    type filter hook input priority 0;\n")
	buf.WriteString("    policy drop;\n")
	buf.WriteString("    iifname \"lo\" accept;\n")
	buf.WriteString("    ct state { established, related } accept;\n")
	// Allow management-plane to talk to engine internal API.
	buf.WriteString("    tcp dport 8081 accept;\n")
	// Local service allow rules (mgmt/ssh/vpn). Deterministic ordering.
	locals := append([]rules.LocalServiceRule(nil), snap.LocalInput...)
	sort.Slice(locals, func(i, j int) bool { return locals[i].ID < locals[j].ID })
	for _, lr := range locals {
		line, err := compileLocalInputRule(lr, snap.ZoneIfaces)
		if err != nil {
			return "", err
		}
		if line == "" {
			continue
		}
		buf.WriteString("    " + line + ";\n")
	}
	buf.WriteString("  }\n")
	buf.WriteString("  chain forward {\n")
	buf.WriteString("    type filter hook forward priority 0;\n")
	buf.WriteString(fmt.Sprintf("    policy %s;\n", defaultPolicy(snap.Default)))
	buf.WriteString("    ct state { established, related } accept;\n")
	// Dynamic blocks first (verdict-driven).
	buf.WriteString("    ip saddr @block_hosts drop;\n")
	buf.WriteString("    ip daddr @block_hosts drop;\n")
	buf.WriteString("    meta l4proto { tcp, udp } ip saddr . ip daddr . th dport @block_flows drop;\n")

	entries := append([]rules.Entry(nil), snap.Firewall...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	for _, e := range entries {
		line, err := compileEntry(e, snap.ZoneIfaces)
		if err != nil {
			return "", err
		}
		buf.WriteString("    " + line + ";\n")
	}
	buf.WriteString("  }\n")

	// PREROUTING NAT: DNAT port forwards (simple destination NAT).
	if len(snap.NAT.PortForwards) > 0 && len(snap.ZoneIfaces) > 0 {
		entries := append([]rules.PortForward(nil), snap.NAT.PortForwards...)
		sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
		buf.WriteString("  chain prerouting {\n")
		buf.WriteString("    type nat hook prerouting priority dstnat;\n")
		buf.WriteString("    policy accept;\n")
		for _, pf := range entries {
			if !pf.Enabled {
				continue
			}
			ingress := strings.TrimSpace(pf.IngressZone)
			if ingress == "" {
				continue
			}
			proto := strings.ToLower(strings.TrimSpace(pf.Proto))
			if proto != "tcp" && proto != "udp" {
				continue
			}
			if pf.ListenPort <= 0 || pf.ListenPort > 65535 {
				continue
			}
			dstIP := strings.TrimSpace(pf.DestIP)
			if net.ParseIP(dstIP) == nil {
				continue
			}
			dstPort := pf.DestPort
			if dstPort == 0 {
				dstPort = pf.ListenPort
			}
			if dstPort < 1 || dstPort > 65535 {
				continue
			}

			ingSet := "zone_" + sanitizeIdent(ingress) + "_ifaces"
			parts := []string{
				fmt.Sprintf("iifname @%s", ingSet),
			}
			if len(pf.AllowedSources) > 0 {
				parts = append(parts, fmt.Sprintf("ip saddr { %s }", strings.Join(pf.AllowedSources, ", ")))
			}
			parts = append(parts, proto, fmt.Sprintf("dport %d", pf.ListenPort), "counter")
			if dstPort > 0 && dstPort != pf.ListenPort {
				parts = append(parts, fmt.Sprintf("dnat ip to %s:%d", dstIP, dstPort))
			} else {
				parts = append(parts, fmt.Sprintf("dnat ip to %s", dstIP))
			}
			buf.WriteString("    " + strings.Join(parts, " ") + ";\n")
		}
		buf.WriteString("  }\n")
	}

	// POSTROUTING NAT: source NAT (masquerade) for common lab/appliance setups.
	if snap.NAT.Enabled && len(snap.ZoneIfaces) > 0 {
		egress := strings.TrimSpace(snap.NAT.EgressZone)
		if egress == "" {
			egress = "wan"
		}
		srcZones := snap.NAT.SourceZones
		if len(srcZones) == 0 {
			srcZones = []string{"lan", "dmz"}
		}
		buf.WriteString("  chain postrouting {\n")
		buf.WriteString("    type nat hook postrouting priority srcnat;\n")
		buf.WriteString("    policy accept;\n")
		// Ensure DNAT'd traffic from wan -> lan returns via engine (SNAT/masq).
		if len(snap.NAT.PortForwards) > 0 {
			buf.WriteString("    iifname @zone_wan_ifaces oifname @zone_lan_ifaces masquerade;\n")
		}
		for _, z := range srcZones {
			z = strings.TrimSpace(z)
			if z == "" {
				continue
			}
			srcSet := "zone_" + sanitizeIdent(z) + "_ifaces"
			egSet := "zone_" + sanitizeIdent(egress) + "_ifaces"
			buf.WriteString(fmt.Sprintf("    iifname @%s oifname @%s masquerade;\n", srcSet, egSet))
		}
		buf.WriteString("  }\n")
	}

	buf.WriteString("}\n")
	return buf.String(), nil
}

func defaultPolicy(a rules.Action) string {
	if a == rules.ActionAllow {
		return "accept"
	}
	return "drop"
}

func compileEntry(e rules.Entry, zoneIfaces map[string][]string) (string, error) {
	parts := []string{}

	if len(e.SourceZones) > 0 {
		ifs := collectZoneIfaces(e.SourceZones, zoneIfaces)
		if len(ifs) > 0 {
			parts = append(parts, fmt.Sprintf("iifname { %s }", strings.Join(ifs, ", ")))
		} else {
			// No interfaces for these zones -> rule never matches.
			parts = append(parts, "iifname { }")
		}
	}
	if len(e.DestZones) > 0 {
		ifs := collectZoneIfaces(e.DestZones, zoneIfaces)
		if len(ifs) > 0 {
			parts = append(parts, fmt.Sprintf("oifname { %s }", strings.Join(ifs, ", ")))
		} else {
			parts = append(parts, "oifname { }")
		}
	}

	if len(e.Protocols) > 0 {
		// Only first protocol supported in skeleton.
		p := e.Protocols[0]
		if p.Name != "" {
			parts = append(parts, p.Name)
		}
		if p.Port != "" {
			parts = append(parts, fmt.Sprintf("dport %s", p.Port))
		}
	}

	// CIDR matching (skeleton uses ip saddr/daddr; no v6 yet).
	if len(e.Sources) > 0 {
		parts = append(parts, fmt.Sprintf("ip saddr { %s }", strings.Join(e.Sources, ", ")))
	}
	if len(e.Destinations) > 0 {
		parts = append(parts, fmt.Sprintf("ip daddr { %s }", strings.Join(e.Destinations, ", ")))
	}

	switch e.Action {
	case rules.ActionAllow:
		parts = append(parts, "accept")
	case rules.ActionDeny:
		parts = append(parts, "drop")
	default:
		return "", fmt.Errorf("unknown action %q in entry %s", e.Action, e.ID)
	}
	return strings.Join(parts, " "), nil
}

func compileLocalInputRule(r rules.LocalServiceRule, zoneIfaces map[string][]string) (string, error) {
	proto := strings.ToLower(strings.TrimSpace(r.Proto))
	if proto != "tcp" && proto != "udp" {
		return "", fmt.Errorf("local input %s invalid proto %q", r.ID, r.Proto)
	}
	if r.Port < 1 || r.Port > 65535 {
		return "", fmt.Errorf("local input %s invalid port %d", r.ID, r.Port)
	}

	parts := []string{}
	if len(r.Ifaces) > 0 {
		ifs := append([]string(nil), r.Ifaces...)
		sort.Strings(ifs)
		for i, v := range ifs {
			ifs[i] = fmt.Sprintf("\"%s\"", v)
		}
		parts = append(parts, fmt.Sprintf("iifname { %s }", strings.Join(ifs, ", ")))
	} else if strings.TrimSpace(r.Zone) != "" {
		z := strings.TrimSpace(r.Zone)
		if len(zoneIfaces[z]) == 0 {
			// No interfaces for this zone -> rule never matches, omit.
			return "", nil
		}
		setName := "zone_" + sanitizeIdent(z) + "_ifaces"
		parts = append(parts, fmt.Sprintf("iifname @%s", setName))
	}
	parts = append(parts, proto, fmt.Sprintf("dport %d", r.Port), "accept")
	return strings.Join(parts, " "), nil
}

func collectZoneIfaces(zones []string, zoneIfaces map[string][]string) []string {
	if len(zones) == 0 || len(zoneIfaces) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	for _, z := range zones {
		ifs := zoneIfaces[z]
		for _, iface := range ifs {
			if _, ok := seen[iface]; ok {
				continue
			}
			seen[iface] = struct{}{}
			out = append(out, fmt.Sprintf("\"%s\"", iface))
		}
	}
	sort.Strings(out)
	return out
}

func sanitizeIdent(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	out := strings.Builder{}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			out.WriteRune(r)
			continue
		}
		if r == '-' || r == ' ' {
			out.WriteRune('_')
		}
	}
	if out.Len() == 0 {
		return "zone"
	}
	return out.String()
}

// Applier installs an nftables ruleset.
type Applier interface {
	Apply(ctx context.Context, ruleset string) error
}

// NftApplier uses the system `nft` binary.
type NftApplier struct {
	Path string
}

func NewNftApplier() *NftApplier {
	return &NftApplier{Path: "nft"}
}

func (a *NftApplier) Apply(ctx context.Context, ruleset string) error {
	if strings.TrimSpace(ruleset) == "" {
		return errors.New("ruleset is empty")
	}
	path := a.Path
	if path == "" {
		path = "nft"
	}
	cmd := exec.CommandContext(ctx, path, "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft apply failed: %w: %s", err, string(out))
	}
	return nil
}

// Updater performs verdict-driven dynamic updates against nftables sets/maps.
type Updater interface {
	BlockHostTemp(ctx context.Context, ip net.IP, ttl time.Duration) error
	BlockFlowTemp(ctx context.Context, srcIP, dstIP net.IP, proto string, dport string, ttl time.Duration) error
}

// NftUpdater uses the system `nft` binary to update dynamic sets.
type NftUpdater struct {
	Path      string
	TableName string
}

func NewNftUpdater(table string) *NftUpdater {
	if table == "" {
		table = "containd"
	}
	return &NftUpdater{Path: "nft", TableName: table}
}

func (u *NftUpdater) BlockHostTemp(ctx context.Context, ip net.IP, ttl time.Duration) error {
	if ip == nil || ip.To4() == nil {
		return errors.New("invalid IPv4 address")
	}
	args := u.buildBlockHostArgs(ip, ttl)
	return u.run(ctx, args)
}

func (u *NftUpdater) BlockFlowTemp(ctx context.Context, srcIP, dstIP net.IP, proto string, dport string, ttl time.Duration) error {
	if srcIP == nil || srcIP.To4() == nil || dstIP == nil || dstIP.To4() == nil {
		return errors.New("invalid IPv4 flow endpoints")
	}
	if proto != "tcp" && proto != "udp" {
		return fmt.Errorf("unsupported proto %q", proto)
	}
	if dport == "" {
		return errors.New("dport required")
	}
	if _, err := strconv.Atoi(dport); err != nil {
		return fmt.Errorf("invalid dport %q", dport)
	}
	args := u.buildBlockFlowArgs(srcIP, dstIP, dport, ttl)
	return u.run(ctx, args)
}

func (u *NftUpdater) buildBlockHostArgs(ip net.IP, ttl time.Duration) []string {
	setName := "block_hosts"
	ipStr := ip.To4().String()
	elem := ipStr
	if ttl > 0 {
		elem = fmt.Sprintf("%s timeout %ds", ipStr, int(ttl.Seconds()))
	}
	return []string{"add", "element", "inet", u.TableName, setName, "{", elem, "}"}
}

func (u *NftUpdater) buildBlockFlowArgs(srcIP, dstIP net.IP, dport string, ttl time.Duration) []string {
	setName := "block_flows"
	key := fmt.Sprintf("%s . %s . %s", srcIP.To4().String(), dstIP.To4().String(), dport)
	elem := key
	if ttl > 0 {
		elem = fmt.Sprintf("%s timeout %ds", key, int(ttl.Seconds()))
	}
	return []string{"add", "element", "inet", u.TableName, setName, "{", elem, "}"}
}

func (u *NftUpdater) run(ctx context.Context, args []string) error {
	path := u.Path
	if path == "" {
		path = "nft"
	}
	cmd := exec.CommandContext(ctx, path, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft update failed: %w: %s", err, string(out))
	}
	return nil
}
