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

	"github.com/tonylturner/containd/pkg/common/mgmtpath"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// Compiler turns a dp rules.Snapshot into an nftables ruleset.
// This is a minimal Phase 1 skeleton.
type Compiler struct {
	ManagementReservation *mgmtpath.Reservation
	// EngineAPI is the non-loopback path to the engine API, or nil for none.
	EngineAPI *EngineAPIPath
	TableName string
	// QueueID, when non-zero, causes DPI-eligible rules (those with an
	// ICS predicate) to emit "queue num <QueueID>" instead of accept/drop,
	// steering matched traffic through NFQUEUE for selective DPI.
	QueueID int
	// IEC104EnvelopeOpen is the state CompileFirewall writes into
	// IEC104EnvelopeChain: true queues envelope traffic to QueueID, false
	// (the zero value) drops it. Only the engine that owns the queue sets
	// it, and only while that queue is bound.
	IEC104EnvelopeOpen bool
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
	// ScheduleFrom and ScheduleHorizon bound the windows written to schedule
	// time sets: [ScheduleFrom, ScheduleFrom+ScheduleHorizon). Zero values
	// mean now and DefaultScheduleHorizon (see schedule.go).
	ScheduleFrom    time.Time
	ScheduleHorizon time.Duration
}

func NewCompiler() *Compiler {
	return &Compiler{TableName: defaultTableName}
}

// CompileFirewall builds the nft script for the snapshot: one transaction
// that replaces the policy table and ensures the dynamic table (see
// tables.go). No other table in the namespace is touched.
func (c *Compiler) CompileFirewall(snap *rules.Snapshot) (string, error) {
	if snap == nil {
		return "", errors.New("snapshot is nil")
	}
	if err := ValidateTableName(c.DynamicTable()); err != nil {
		return "", err
	}
	table := c.policyTable()
	locals, err := resolveLocalInput(snap)
	if err != nil {
		return "", err
	}

	preds, err := newPredicates(snap, c.QueueID)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	buf.WriteString(DeleteTable(table))
	buf.WriteString(fmt.Sprintf("table inet %s {\n", table))
	preds.zones.writeSets(&buf)
	if err := writeRuleObjects(&buf, snap); err != nil {
		return "", err
	}
	if err := preds.writeSets(&buf, c); err != nil {
		return "", err
	}
	if err := preds.writeRecheckChains(&buf); err != nil {
		return "", err
	}
	// Declared before the forward chain that jumps to it.
	if c.SteersIEC104(snap) {
		c.writeIEC104EnvelopeChain(&buf)
	}
	if err := c.writeInputChain(&buf, preds.zones, locals); err != nil {
		return "", err
	}
	if err := c.writeForwardChain(&buf, snap, preds); err != nil {
		return "", err
	}
	if err := c.writePreroutingChain(&buf, snap); err != nil {
		return "", err
	}
	if err := c.writePostroutingChain(&buf, snap); err != nil {
		return "", err
	}
	buf.WriteString("}\n")
	if err := c.writeDynamicTable(&buf, locals); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// writeInputChain emits the input chain; locals is snap's local input,
// resolved by resolveLocalInput.
func (c *Compiler) writeInputChain(buf *bytes.Buffer, zones zoneIndex, locals []rules.LocalServiceRule) error {
	buf.WriteString("  chain input {\n")
	buf.WriteString("    type filter hook input priority 0;\n")
	buf.WriteString("    policy drop;\n")
	buf.WriteString("    iifname \"lo\" accept;\n")
	buf.WriteString("    ct state { established, related } accept;\n")
	buf.WriteString("    ct state invalid drop;\n")
	if err := c.writeManagementInput(buf); err != nil {
		return err
	}
	buf.WriteString("    ip protocol icmp icmp type { echo-request, echo-reply, destination-unreachable, time-exceeded } accept;\n")
	buf.WriteString("    meta l4proto ipv6-icmp icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, destination-unreachable, packet-too-big, time-exceeded, parameter-problem } accept;\n")
	if err := c.writeEngineAPIInput(buf); err != nil {
		return err
	}
	for _, lr := range locals {
		line, err := compileLocalInputRule(lr, zones)
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

func (c *Compiler) writeForwardChain(buf *bytes.Buffer, snap *rules.Snapshot, preds *predicates) error {
	buf.WriteString("  chain forward {\n")
	buf.WriteString("    type filter hook forward priority 0;\n")
	buf.WriteString(fmt.Sprintf("    policy %s;\n", defaultPolicy(snap.Default)))
	// Revocations and temporary blocks act in the dynamic table's earlier
	// forward chain, before anything below (see writeDynamicTable).

	// RATE_LIMIT meters come first, so that they meter every packet of a
	// flow, before IEC104 steering, NFQUEUE and the established accept.
	meters, tags, decide := forwardSections(snap.Firewall)
	if err := c.writeEntries(buf, preds, meters); err != nil {
		return err
	}

	// Emit dpiEligible rules (those with ICS predicates compiled to
	// `queue num N`) BEFORE the ct established fast-path. Otherwise only
	// the SYN of an inspected flow reaches the queue — subsequent data-
	// bearing packets (the ones actually carrying the Modbus/DNP3/CIP
	// PDU we need to inspect) match ct established and skip the queue
	// entirely, so the userspace DPI decoder never sees a payload to
	// parse. With QueueID=0 this is a no-op (compileEntry emits plain
	// accept/drop for everything, ct established below stays optimal).
	// IEC104 rules come first and steer both directions of their session
	// scope, marked; they replace the rule's own line.
	if c.QueueID > 0 {
		if err := c.writeIEC104Steering(func(line string) { buf.WriteString("    " + line + ";\n") }, snap, preds.zones); err != nil {
			return err
		}
		var queued []rules.Entry
		for _, e := range decide {
			if isDPIEligible(e) && !isIEC104Rule(e) {
				queued = append(queued, e)
			}
		}
		if err := c.writeEntries(buf, preds, queued); err != nil {
			return err
		}
	}

	preds.writeRecheckJump(buf)
	buf.WriteString("    ct state { established, related } accept;\n")
	if err := c.writeDNATAccepts(buf, snap); err != nil {
		return err
	}
	// Emit non-dpiEligible rules after the conntrack fast-path so plain
	// L4 traffic gets the established-flow optimization. dpiEligible
	// rules already emitted above with QueueID > 0 are skipped here. TAG
	// lines only count and continue. nftables is first-match, so every
	// ALLOW emits before every DENY and RESET (rules.DecisionOrder): any
	// matching ALLOW wins.
	var rest []rules.Entry
	for _, e := range append(tags, decide...) {
		if !queuedToEngine(e, c.QueueID) {
			rest = append(rest, e)
		}
	}
	if err := c.writeEntries(buf, preds, rest); err != nil {
		return err
	}
	buf.WriteString("  }\n")
	return nil
}

// writeEntries emits the lines of entries in order, with their identity
// and schedule predicates.
func (c *Compiler) writeEntries(buf *bytes.Buffer, preds *predicates, entries []rules.Entry) error {
	for _, e := range entries {
		lines, err := compileEntry(e, preds.zones, c.QueueID, c.NFLogGroup)
		if err != nil {
			return err
		}
		guarded, err := preds.guard(e, lines)
		if err != nil {
			return err
		}
		for _, line := range guarded {
			buf.WriteString("    " + line + ";\n")
		}
	}
	return nil
}

func defaultPolicy(a rules.Action) string {
	if a == rules.ActionAllow {
		return "accept"
	}
	return "drop"
}

// ruleLine is one nft line of a rule, before its identity and schedule
// predicates (predicates.guard).
type ruleLine struct {
	// family is the address family the line is restricted to, or
	// familyAny.
	family int
	// ct marks a line that matches packets of both directions by their
	// connection's original tuple; its predicates must too.
	ct   bool
	text string
}

// compileEntry returns the lines of one rule: one per protocol (a rule
// without protocols matches every protocol) and address family, and, for
// RESET and RATE_LIMIT, per form of the action (actionForms, meterLines).
// A rule that can match nothing, because its zones have no interfaces or
// its sources and destinations share no address family, has no lines.
//
// Identity and schedule predicates are not part of these lines: the forward
// chain adds them (predicates.guard).
//
// Each line counts into the rule's counter.
func compileEntry(e rules.Entry, zones zoneIndex, queueID int, nflogGroup int) ([]ruleLine, error) {
	scopes, err := addrScopes(e)
	if err != nil {
		return nil, err
	}
	in, inOK := zones.clause("iifname", e.SourceZones)
	out, outOK := zones.clause("oifname", e.DestZones)
	if !inOK || !outOK || len(scopes) == 0 {
		return nil, nil
	}
	queued := queuedToEngine(e, queueID)

	// Build the optional log statement. Only emit for non-DPI rules:
	// DPI-eligible rules already get visibility through the NFQUEUE
	// userspace path (RecordDPIEvents → eventStore.Record, plus the
	// firewall.rule.hit event from EvaluateVerdict when an enforce-mode
	// verdict is applied). Adding a kernel log here would double-count.
	logStmt := ""
	if e.Log && nflogGroup > 0 && !isDPIEligible(e) {
		logStmt = fmt.Sprintf(`log prefix "%s" group %d`, logPrefix(e.ID, e.Action), nflogGroup)
	}

	protos := e.Protocols
	if len(protos) == 0 {
		protos = []rules.Protocol{{}}
	}
	var lines []ruleLine
	for _, p := range protos {
		if e.Action == rules.ActionRateLimit && !queued {
			metered, err := meterLines(e, p, scopes, zones, logStmt)
			if err != nil {
				return nil, err
			}
			lines = append(lines, metered...)
			continue
		}
		forms, err := actionForms(e, p, queued, queueID, counterStmt(e.ID), logStmt)
		if err != nil {
			return nil, err
		}
		match, err := protocolMatch(p)
		if err != nil {
			return nil, fmt.Errorf("entry %s: %w", e.ID, err)
		}
		for _, s := range scopes {
			for _, f := range forms {
				parts := append([]string{f.match, in, out, match}, s.header(false)...)
				lines = append(lines, ruleLine{family: s.family, text: joinClauses(append(parts, f.stmts))})
			}
		}
	}
	return lines, nil
}

// protocolMatch returns the nft match for one rule protocol. A transport
// with a port matches on its destination port; a transport without one,
// or ICMP, matches on the layer-4 protocol alone (a bare "tcp" token is
// not a valid nft expression). An empty protocol matches everything.
func protocolMatch(p rules.Protocol) (string, error) {
	name := strings.ToLower(strings.TrimSpace(p.Name))
	switch name {
	case "":
		if p.Port != "" {
			return "", fmt.Errorf("port %q needs a tcp or udp protocol", p.Port)
		}
		return "", nil
	case "tcp", "udp":
		if p.Port == "" {
			return "meta l4proto " + name, nil
		}
		lo, hi, err := rules.ParsePortRange(p.Port)
		if err != nil {
			return "", fmt.Errorf("invalid %s port: %w", name, err)
		}
		if lo == hi {
			return fmt.Sprintf("%s dport %d", name, lo), nil
		}
		return fmt.Sprintf("%s dport %d-%d", name, lo, hi), nil
	case "icmp":
		if p.Port != "" {
			return "", fmt.Errorf("icmp does not take a port (got %q)", p.Port)
		}
		return "meta l4proto icmp", nil
	default:
		return "", fmt.Errorf("unsupported protocol %q", p.Name)
	}
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

// RulePredicate names the part of a rule a warning is about.
type RulePredicate string

const (
	// PredicateIdentity: no bound address satisfies the rule's identities.
	PredicateIdentity RulePredicate = "identity"
	// PredicateZone: none of the rule's source or destination zones has
	// an interface (RuleWarning.Zones).
	PredicateZone RulePredicate = "zone"
	// PredicateAddressFamily: the rule's sources and destinations share no
	// address family.
	PredicateAddressFamily RulePredicate = "addressFamily"
)

// RuleWarning reports a firewall rule that does not act as written: one
// that matches nothing, because of the part of the rule Predicate names, or
// a DENY or RESET rule that an ALLOW shadows (ShadowedBy).
type RuleWarning struct {
	RuleID     string        `json:"ruleId"`
	Predicate  RulePredicate `json:"predicate,omitempty"`
	Zones      []string      `json:"zones,omitempty"`
	ShadowedBy string        `json:"shadowedBy,omitempty"`
	Action     rules.Action  `json:"action"`
	Message    string        `json:"message"`
}

// RuleWarnings lists, in rule ID order, snap's firewall rules that match
// nothing (zoneWarnings, familyWarnings, identityWarnings), and every DENY
// or RESET rule an ALLOW shadows (shadowWarnings).
func (c *Compiler) RuleWarnings(snap *rules.Snapshot) []RuleWarning {
	if snap == nil {
		return nil
	}
	idx, err := newIdentityIndex(snap.IdentityBindings)
	if err != nil {
		return nil // such a snapshot does not compile, so it has no ruleset to warn about
	}
	zones, err := newZoneIndex(snap.ZoneIfaces)
	if err != nil {
		return nil // likewise
	}
	out := zoneWarnings(snap, zones)
	out = append(out, familyWarnings(snap)...)
	out = append(out, identityWarnings(snap, idx)...)
	out = append(out, shadowWarnings(snap)...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].RuleID < out[j].RuleID })
	return out
}

// isDPIEligible returns true if an entry requires DPI/ICS inspection and
// should therefore be steered through NFQUEUE when a queue ID is configured.
func isDPIEligible(e rules.Entry) bool {
	return e.ICS.Protocol != ""
}

// queuedToEngine reports whether e's traffic is queued to the engine,
// which then decides it, instead of being accepted or dropped by nftables.
func queuedToEngine(e rules.Entry, queueID int) bool {
	return queueID > 0 && isDPIEligible(e)
}

func compileLocalInputRule(r rules.LocalServiceRule, zones zoneIndex) (string, error) {
	proto := strings.ToLower(strings.TrimSpace(r.Proto))
	if proto != "tcp" && proto != "udp" {
		return "", fmt.Errorf("local input %s invalid proto %q", r.ID, r.Proto)
	}
	if r.Port < 1 || r.Port > 65535 {
		return "", fmt.Errorf("local input %s invalid port %d", r.ID, r.Port)
	}

	parts := []string{}
	if len(r.Ifaces) > 0 {
		set, err := ifnameSet(r.Ifaces)
		if err != nil {
			return "", fmt.Errorf("local input %s: %w", r.ID, err)
		}
		parts = append(parts, "iifname "+set)
	} else if z := strings.TrimSpace(r.Zone); z != "" {
		if len(zones[z]) == 0 {
			// No interfaces for this zone -> rule never matches, omit.
			return "", nil
		}
		parts = append(parts, "iifname @"+zoneSetName(z))
	}
	parts = append(parts, proto, fmt.Sprintf("dport %d", r.Port), "accept")
	return strings.Join(parts, " "), nil
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

// Applier installs an nftables ruleset and reads the live layout of a
// dynamic table, so an install can converge it (see InstallScript).
type Applier interface {
	Apply(ctx context.Context, ruleset string) error
	ReadTable(ctx context.Context, table string) (TableLayout, error)
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

// NftUpdater uses the system `nft` binary to update the block sets.
type NftUpdater struct {
	Path string
	// TableName is the dynamic table that holds the sets.
	TableName string
}

// NewNftUpdater returns an updater for the dynamic table named table
// (default containd).
func NewNftUpdater(table string) *NftUpdater {
	if table == "" {
		table = defaultTableName
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
	if port, err := strconv.Atoi(dport); err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid dport %q", dport)
	}
	args := u.buildBlockFlowArgs(srcIP, dstIP, proto, dport, ttl)
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

func (u *NftUpdater) buildBlockFlowArgs(srcIP, dstIP net.IP, proto, dport string, ttl time.Duration) []string {
	setName := "block_flows"
	key := fmt.Sprintf("%s . %s . %s . %s", srcIP.To4().String(), dstIP.To4().String(), proto, dport)
	elem := key
	if ttl > 0 {
		elem = fmt.Sprintf("%s timeout %ds", key, int(ttl.Seconds()))
	}
	return []string{"add", "element", "inet", u.TableName, setName, "{", elem, "}"}
}

func (u *NftUpdater) run(ctx context.Context, args []string) error {
	if err := ValidateTableName(u.TableName); err != nil {
		return err
	}
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
