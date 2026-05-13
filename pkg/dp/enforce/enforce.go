// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

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

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// Compiler turns a dp rules.Snapshot into an nftables ruleset.
// This is a minimal Phase 1 skeleton.
type Compiler struct {
	TableName string
	// QueueID, when non-zero, causes DPI-eligible rules (those with an
	// ICS predicate) to emit "queue num <QueueID>" instead of accept/drop,
	// steering matched traffic through NFQUEUE for selective DPI.
	QueueID int
	// NFLogGroup, when non-zero, causes rules with Log:true to emit a
	// "log prefix ... group <NFLogGroup>" statement before their verdict.
	// The userspace nflog consumer subscribes to this group, parses the
	// prefix to recover (ruleId, action), and appends firewall.rule.hit
	// events to the engine's event store — this is how L4-only rules
	// (no ICS predicate, so no NFQUEUE handoff) become visible in
	// /api/v1/events. DPI-eligible rules emit their visibility through
	// the existing NFQUEUE userspace path, so this log statement is
	// suppressed for them to avoid double-counting.
	NFLogGroup int
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
	c.writeZoneIfaceSets(&buf, snap)
	c.writeDynamicSets(&buf)
	if err := c.writeInputChain(&buf, snap); err != nil {
		return "", err
	}
	if err := c.writeForwardChain(&buf, snap); err != nil {
		return "", err
	}
	if err := c.writePreroutingChain(&buf, snap); err != nil {
		return "", err
	}
	c.writePostroutingChain(&buf, snap)
	buf.WriteString("}\n")
	return buf.String(), nil
}

func (c *Compiler) writeZoneIfaceSets(buf *bytes.Buffer, snap *rules.Snapshot) {
	if len(snap.ZoneIfaces) == 0 {
		return
	}
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

func (c *Compiler) writeDynamicSets(buf *bytes.Buffer) {
	buf.WriteString("  set block_hosts {\n")
	buf.WriteString("    type ipv4_addr;\n")
	buf.WriteString("    flags timeout;\n")
	buf.WriteString("  }\n")
	buf.WriteString("  set block_flows {\n")
	buf.WriteString("    type ipv4_addr . ipv4_addr . inet_service;\n")
	buf.WriteString("    flags timeout;\n")
	buf.WriteString("  }\n")
}

func (c *Compiler) writeInputChain(buf *bytes.Buffer, snap *rules.Snapshot) error {
	buf.WriteString("  chain input {\n")
	buf.WriteString("    type filter hook input priority 0;\n")
	buf.WriteString("    policy drop;\n")
	buf.WriteString("    iifname \"lo\" accept;\n")
	buf.WriteString("    ct state { established, related } accept;\n")
	buf.WriteString("    ct state invalid drop;\n")
	buf.WriteString("    ip protocol icmp icmp type { echo-request, echo-reply, destination-unreachable, time-exceeded } accept;\n")
	buf.WriteString("    tcp dport 8081 accept;\n")
	locals := append([]rules.LocalServiceRule(nil), snap.LocalInput...)
	sort.Slice(locals, func(i, j int) bool { return locals[i].ID < locals[j].ID })
	for _, lr := range locals {
		line, err := compileLocalInputRule(lr, snap.ZoneIfaces)
		if err != nil {
			return err
		}
		if line == "" {
			continue
		}
		buf.WriteString("    " + line + ";\n")
	}
	buf.WriteString("  }\n")
	return nil
}

func (c *Compiler) writeForwardChain(buf *bytes.Buffer, snap *rules.Snapshot) error {
	buf.WriteString("  chain forward {\n")
	buf.WriteString("    type filter hook forward priority 0;\n")
	buf.WriteString(fmt.Sprintf("    policy %s;\n", defaultPolicy(snap.Default)))

	// block_hosts/block_flows must fire BEFORE ct established so that
	// retroactive blocks (added by enforceDPIEvents.ApplyVerdict when a
	// DPI verdict denies a function-code-violating Modbus PDU, for
	// example) actually drop subsequent packets of an already-established
	// flow. Without this ordering, ct established below would short-
	// circuit and the block_flows entry would only catch new flows.
	buf.WriteString("    ip saddr @block_hosts drop;\n")
	buf.WriteString("    ip daddr @block_hosts drop;\n")
	buf.WriteString("    meta l4proto { tcp, udp } ip saddr . ip daddr . th dport @block_flows drop;\n")

	entries := append([]rules.Entry(nil), snap.Firewall...)
	sort.SliceStable(entries, func(i, j int) bool {
		ai, aj := entries[i].Action, entries[j].Action
		if ai != aj {
			return ai == rules.ActionAllow
		}
		return entries[i].ID < entries[j].ID
	})

	// Emit dpiEligible rules (those with ICS predicates compiled to
	// `queue num N`) BEFORE the ct established fast-path. Otherwise only
	// the SYN of an inspected flow reaches the queue — subsequent data-
	// bearing packets (the ones actually carrying the Modbus/DNP3/CIP
	// PDU we need to inspect) match ct established and skip the queue
	// entirely, so the userspace DPI decoder never sees a payload to
	// parse. With QueueID=0 this is a no-op (compileEntry emits plain
	// accept/drop for everything, ct established below stays optimal).
	if c.QueueID > 0 {
		for _, e := range entries {
			if !isDPIEligible(e) {
				continue
			}
			lines, err := compileEntry(e, snap.ZoneIfaces, c.QueueID, c.NFLogGroup)
			if err != nil {
				return err
			}
			for _, line := range lines {
				buf.WriteString("    " + line + ";\n")
			}
		}
	}

	buf.WriteString("    ct state { established, related } accept;\n")
	if err := c.writeDNATAccepts(buf, snap); err != nil {
		return err
	}
	// Emit non-dpiEligible rules after the conntrack fast-path so plain
	// L4 traffic gets the established-flow optimization. dpiEligible
	// rules already emitted above with QueueID > 0 are skipped here.
	// nftables is first-match, so ALLOW exceptions (more specific) must
	// emit before DENY rules (broader) — preserved by the sort above.
	for _, e := range entries {
		if c.QueueID > 0 && isDPIEligible(e) {
			continue
		}
		lines, err := compileEntry(e, snap.ZoneIfaces, c.QueueID, c.NFLogGroup)
		if err != nil {
			return err
		}
		for _, line := range lines {
			buf.WriteString("    " + line + ";\n")
		}
	}
	buf.WriteString("  }\n")
	return nil
}

func (c *Compiler) writeDNATAccepts(buf *bytes.Buffer, snap *rules.Snapshot) error {
	if len(snap.NAT.PortForwards) == 0 || len(snap.ZoneIfaces) == 0 {
		return nil
	}
	pfs := append([]rules.PortForward(nil), snap.NAT.PortForwards...)
	sort.Slice(pfs, func(i, j int) bool { return pfs[i].ID < pfs[j].ID })
	for _, pf := range pfs {
		line, err := compileDNATAccept(pf)
		if err != nil {
			return err
		}
		if line != "" {
			buf.WriteString("    " + line + ";\n")
		}
	}
	return nil
}

func (c *Compiler) writePreroutingChain(buf *bytes.Buffer, snap *rules.Snapshot) error {
	if len(snap.NAT.PortForwards) == 0 || len(snap.ZoneIfaces) == 0 {
		return nil
	}
	entries := append([]rules.PortForward(nil), snap.NAT.PortForwards...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	buf.WriteString("  chain prerouting {\n")
	buf.WriteString("    type nat hook prerouting priority dstnat;\n")
	buf.WriteString("    policy accept;\n")
	for _, pf := range entries {
		line, err := compilePreroutingDNAT(pf)
		if err != nil {
			return err
		}
		if line != "" {
			buf.WriteString("    " + line + ";\n")
		}
	}
	buf.WriteString("  }\n")
	return nil
}

func (c *Compiler) writePostroutingChain(buf *bytes.Buffer, snap *rules.Snapshot) {
	if !snap.NAT.Enabled || len(snap.ZoneIfaces) == 0 {
		return
	}
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

func compileDNATAccept(pf rules.PortForward) (string, error) {
	if !pf.Enabled {
		return "", nil
	}
	ingress := strings.TrimSpace(pf.IngressZone)
	if ingress == "" {
		return "", nil
	}
	proto := strings.ToLower(strings.TrimSpace(pf.Proto))
	if proto != "tcp" && proto != "udp" {
		return "", nil
	}
	if pf.ListenPort < 1 || pf.ListenPort > 65535 {
		return "", nil
	}
	dstPort := pf.DestPort
	if dstPort == 0 {
		dstPort = pf.ListenPort
	}
	if dstPort < 1 || dstPort > 65535 {
		return "", nil
	}
	ingSet := "zone_" + sanitizeIdent(ingress) + "_ifaces"
	parts := []string{
		fmt.Sprintf("iifname @%s", ingSet),
		"ct status dnat",
		proto + " dport " + strconv.Itoa(dstPort),
	}
	if len(pf.AllowedSources) > 0 {
		validated, err := validateCIDRList(pf.AllowedSources)
		if err != nil {
			return "", fmt.Errorf("port forward %s: invalid AllowedSources: %w", pf.ID, err)
		}
		parts = append(parts, fmt.Sprintf("ip saddr { %s }", strings.Join(validated, ", ")))
	}
	parts = append(parts, "accept")
	return strings.Join(parts, " "), nil
}

func compilePreroutingDNAT(pf rules.PortForward) (string, error) {
	if !pf.Enabled {
		return "", nil
	}
	ingress := strings.TrimSpace(pf.IngressZone)
	if ingress == "" {
		return "", nil
	}
	proto := strings.ToLower(strings.TrimSpace(pf.Proto))
	if proto != "tcp" && proto != "udp" {
		return "", nil
	}
	if pf.ListenPort <= 0 || pf.ListenPort > 65535 {
		return "", nil
	}
	dstIP := strings.TrimSpace(pf.DestIP)
	if net.ParseIP(dstIP) == nil {
		return "", nil
	}
	dstPort := pf.DestPort
	if dstPort == 0 {
		dstPort = pf.ListenPort
	}
	if dstPort < 1 || dstPort > 65535 {
		return "", nil
	}
	ingSet := "zone_" + sanitizeIdent(ingress) + "_ifaces"
	parts := []string{fmt.Sprintf("iifname @%s", ingSet)}
	if len(pf.AllowedSources) > 0 {
		validated, err := validateCIDRList(pf.AllowedSources)
		if err != nil {
			return "", fmt.Errorf("port forward %s: invalid AllowedSources: %w", pf.ID, err)
		}
		parts = append(parts, fmt.Sprintf("ip saddr { %s }", strings.Join(validated, ", ")))
	}
	parts = append(parts, proto, fmt.Sprintf("dport %d", pf.ListenPort), "counter")
	if dstPort > 0 && dstPort != pf.ListenPort {
		parts = append(parts, fmt.Sprintf("dnat ip to %s:%d", dstIP, dstPort))
	} else {
		parts = append(parts, fmt.Sprintf("dnat ip to %s", dstIP))
	}
	return strings.Join(parts, " "), nil
}

func defaultPolicy(a rules.Action) string {
	if a == rules.ActionAllow {
		return "accept"
	}
	return "drop"
}

// compileEntry returns one nft rule line per protocol on the entry. Rules
// declaring multiple protocols (e.g. one ALLOW for tcp/502 + tcp/20000 +
// tcp/8080) used to compile to a single nft line for the first protocol
// only — silently dropping every other protocol the operator declared.
// Now each protocol becomes its own line, matching the operator's intent.
//
// Entries with zero protocols emit a single line with no proto/port match
// (relies on zone iifname/oifname or saddr/daddr to constrain the rule).
func compileEntry(e rules.Entry, zoneIfaces map[string][]string, queueID int, nflogGroup int) ([]string, error) {
	base := []string{}

	if len(e.SourceZones) > 0 {
		ifs := collectZoneIfaces(e.SourceZones, zoneIfaces)
		if len(ifs) > 0 {
			base = append(base, fmt.Sprintf("iifname { %s }", strings.Join(ifs, ", ")))
		} else {
			// No interfaces for these zones -> rule never matches.
			base = append(base, "iifname { }")
		}
	}
	if len(e.DestZones) > 0 {
		ifs := collectZoneIfaces(e.DestZones, zoneIfaces)
		if len(ifs) > 0 {
			base = append(base, fmt.Sprintf("oifname { %s }", strings.Join(ifs, ", ")))
		} else {
			base = append(base, "oifname { }")
		}
	}

	// Pick the verdict once — same for every emitted protocol-variant line.
	dpiEligible := isDPIEligible(e)
	verdict := ""
	if queueID > 0 && dpiEligible {
		verdict = fmt.Sprintf("queue num %d", queueID)
	} else {
		switch e.Action {
		case rules.ActionAllow:
			verdict = "accept"
		case rules.ActionDeny:
			verdict = "drop"
		default:
			return nil, fmt.Errorf("unknown action %q in entry %s", e.Action, e.ID)
		}
	}

	// Build the optional log statement. Only emit for non-DPI rules:
	// DPI-eligible rules already get visibility through the NFQUEUE
	// userspace path (RecordDPIEvents → eventStore.Record, plus the
	// firewall.rule.hit event from EvaluateVerdict when an enforce-mode
	// verdict is applied). Adding a kernel log here would double-count.
	logStmt := ""
	if e.Log && nflogGroup > 0 && !dpiEligible {
		logStmt = fmt.Sprintf(`log prefix "%s" group %d`, logPrefix(e.ID, e.Action), nflogGroup)
	}

	// Treat "no protocols" as a single iteration with no proto match — the
	// rule is constrained by zones/CIDRs alone.
	protos := e.Protocols
	if len(protos) == 0 {
		protos = []rules.Protocol{{}}
	}

	lines := make([]string, 0, len(protos))
	for _, p := range protos {
		parts := append([]string(nil), base...)
		if p.Name != "" {
			parts = append(parts, p.Name)
		}
		if p.Port != "" {
			parts = append(parts, fmt.Sprintf("dport %s", p.Port))
		}
		// CIDR matching (skeleton uses ip saddr/daddr; no v6 yet).
		if len(e.Sources) > 0 {
			parts = append(parts, fmt.Sprintf("ip saddr { %s }", strings.Join(e.Sources, ", ")))
		}
		if len(e.Destinations) > 0 {
			parts = append(parts, fmt.Sprintf("ip daddr { %s }", strings.Join(e.Destinations, ", ")))
		}
		if logStmt != "" {
			parts = append(parts, logStmt)
		}
		parts = append(parts, verdict)
		lines = append(lines, strings.Join(parts, " "))
	}
	return lines, nil
}

// logPrefix builds the nflog prefix string for a rule. Format:
//
//	containd:<sanitized-rule-id>:<ACTION><space>
//
// The trailing space is conventional — operators reading kernel logs
// expect a separator between the prefix and packet metadata.
//
// Sanitization (also performed at the nflog consumer side):
//   - Only [A-Za-z0-9_-] from the rule ID survive into the on-wire
//     prefix. Other characters become '_'.
//   - The nflog kernel-side prefix is limited to 64 bytes; truncate
//     the rule ID after sanitization so the full prefix fits.
//
// Why sanitize: containd's config validator doesn't forbid colons or
// double-quote characters in rule IDs. Without sanitization, an ID
// containing `"` would emit broken nft syntax (the prefix is quoted),
// and an ID containing `:` would confuse the parser on the consumer
// side (`:` is the field delimiter). Lossy but predictable.
func logPrefix(ruleID string, action rules.Action) string {
	const maxIDLen = 40
	id := sanitizeRuleIDForLog(ruleID)
	if len(id) > maxIDLen {
		id = id[:maxIDLen]
	}
	return fmt.Sprintf("containd:%s:%s ", id, action)
}

// sanitizeRuleIDForLog replaces any character outside [A-Za-z0-9_-]
// with an underscore. The same predicate is reproduced in the nflog
// consumer's prefix regex so the two sides agree on the safe-char set.
func sanitizeRuleIDForLog(id string) string {
	b := make([]byte, len(id))
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '_', c == '-':
			b[i] = c
		default:
			b[i] = '_'
		}
	}
	return string(b)
}

// isDPIEligible returns true if an entry requires DPI/ICS inspection and
// should therefore be steered through NFQUEUE when a queue ID is configured.
func isDPIEligible(e rules.Entry) bool {
	return e.ICS.Protocol != ""
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

// validateCIDRList validates that each entry is a valid IP address or CIDR
// notation. This prevents injection of arbitrary nftables syntax through
// user-supplied source addresses.
func validateCIDRList(sources []string) ([]string, error) {
	out := make([]string, 0, len(sources))
	for _, s := range sources {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if ip := net.ParseIP(s); ip != nil {
			out = append(out, s)
			continue
		}
		if _, _, err := net.ParseCIDR(s); err == nil {
			out = append(out, s)
			continue
		}
		return nil, fmt.Errorf("invalid source address %q: must be IP or CIDR", s)
	}
	return out, nil
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
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
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
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.CommandContext(ctx, path, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft update failed: %w: %s", err, string(out))
	}
	return nil
}
