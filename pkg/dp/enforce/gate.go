// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// The scanning gate terminates selected new TCP connections in this
// namespace and dials their servers with the client's address. Its nft
// lowering has two parts (the marks and chain names are the steering ABI in
// gate_abi.go):
//
//   - Delivery, emitted whenever both listener ports are set, whatever the
//     selection: gateOutputMarkChain marks the gate's upstream connections
//     (ct UP) from their sockets' SO_MARK; GatePreChain routes the replies
//     of upstream connections and every packet of a gated connection (ct
//     GATE) to the local stack (GateLocalPktMark and the policy routing
//     rule the gate manager installs), by TPROXY to the listener the
//     connection was selected for (GateDeliverChain); a gated packet
//     TPROXY does not deliver, because its listener is gone, is reset there
//     and dropped by the forward chain, never forwarded. The gate's own
//     upstream legs are masqueraded by their SO_MARK (nat.go) and checked
//     against the temporary blocks (tables.go).
//   - Selection, emitted only for an enabled selection: gateSelectChain
//     classifies the first SYN of a new connection after DNAT (gate_select.go)
//     and sends a selected one to GateAdmitChain, whose contents the engine
//     switches with GateAdmitSwitch: deliver it, refuse it with a reset
//     (an ICS endpoint passes ungated, gateICSChain), or pass it ungated.
//
// A gated connection is decided by the firewall policy like a forwarded
// one: the input chain sends its original direction to GateInputChain and
// the output chain its replies to GateReplyChain, both lowered from the
// forward chain's decision graph (gate_policy.go).

// gateSelectChain classifies new SYNs; gateICSChain passes ICS endpoints
// ungated under a refusing admission. Neither is referenced outside the
// compiler.
const (
	gateSelectChain = "gate_select"
	gateICSChain    = "gate_ics"
)

// gateSelectionCtMask holds every connection-mark bit selection writes:
// ungating a connection clears them all.
const gateSelectionCtMask = GateCtMark | GateMasqSelCtMark | GateZoneCtMask

// gateInputJump sends the original direction of a gated connection from
// the input chain to GateInputChain; gateForwardGuard keeps a gated
// connection out of the forward chain.
var (
	gateInputJump    = ctMarkMatch(GateCtMark, GateCtMark) + " ct direction original goto " + GateInputChain
	gateForwardGuard = ctMarkMatch(GateCtMark, GateCtMark) + " drop"
)

// hexMark formats a mark for nft.
func hexMark(mark uint32) string {
	return fmt.Sprintf("0x%08x", mark)
}

// ctMarkMatch matches the connection mark under mask against value.
func ctMarkMatch(mask, value uint32) string {
	return "ct mark & " + hexMark(mask) + " == " + hexMark(value)
}

// pktMarkMatch matches the packet mark under mask against value.
func pktMarkMatch(mask, value uint32) string {
	return "meta mark & " + hexMark(mask) + " == " + hexMark(value)
}

// ctMarkSet sets bits in the connection mark, keeping the others.
func ctMarkSet(bits uint32) string {
	return "ct mark set ct mark | " + hexMark(bits)
}

// ungateStmt clears every selection bit of the connection mark: the
// connection continues as a plain forwarded one.
func ungateStmt() string {
	return "ct mark set ct mark & " + hexMark(^gateSelectionCtMask)
}

// gateZoneClause matches the egress zone index of a gated connection
// against indices.
func gateZoneClause(indices []uint8) string {
	marks := make([]string, 0, len(indices))
	for _, i := range indices {
		marks = append(marks, hexMark(uint32(i)<<GateZoneCtShift))
	}
	marks = sortedUnique(marks)
	if len(marks) == 1 {
		return "ct mark & " + hexMark(GateZoneCtMask) + " == " + marks[0]
	}
	return "ct mark & " + hexMark(GateZoneCtMask) + " == { " + strings.Join(marks, ", ") + " }"
}

// SteersGate reports whether c's rulesets carry the gate: both listener
// ports are set.
func (c *Compiler) SteersGate() bool {
	return c.GatePlainPort != 0 && c.GateMasqPort != 0
}

// validateGate refuses listener ports that name no usable pair.
func (c *Compiler) validateGate() error {
	switch {
	case c.GatePlainPort == 0 && c.GateMasqPort == 0:
		return nil
	case c.GatePlainPort == 0 || c.GateMasqPort == 0:
		return errors.New("gate listener ports: set both the plain and the masquerading port, or neither")
	case c.GatePlainPort == c.GateMasqPort:
		return fmt.Errorf("gate listener ports: the plain and the masquerading port are both %d", c.GatePlainPort)
	}
	return nil
}

// writeGateChains emits the gate's chains: the regular chains before the
// base chains that jump to them, and the policy chains for gated
// connections before the input and output chains.
func (c *Compiler) writeGateChains(buf *bytes.Buffer, snap *rules.Snapshot, preds *predicates) error {
	c.writeGateDeliverChain(buf)
	if err := writeGateICSChain(buf, snap.Gate); err != nil {
		return err
	}
	c.writeGateAdmitChain(buf)
	selecting, err := writeGateSelectChain(buf, snap, preds.zones)
	if err != nil {
		return err
	}
	c.writeGatePreChain(buf, selecting)
	if err := c.writeGateInputChain(buf, snap, preds); err != nil {
		return err
	}
	if err := c.writeGateReplyChain(buf, snap, preds); err != nil {
		return err
	}
	c.writeGateOutputChains(buf)
	return nil
}

// writeGateDeliverChain emits GateDeliverChain: TPROXY of a gated
// connection's packets to the listener its selection chose, marked for
// local delivery. TPROXY matches the listener for a SYN and the accepted
// socket for every later packet; without either it does not match, and
// evaluation continues in the caller.
func (c *Compiler) writeGateDeliverChain(buf *bytes.Buffer) {
	buf.WriteString("  chain " + GateDeliverChain + " {\n")
	for _, rule := range c.gateDeliverRules() {
		buf.WriteString("    " + rule + ";\n")
	}
	buf.WriteString("  }\n")
}

// gateDeliverRules returns GateDeliverChain's rules: the masquerading
// listener for a connection selection marked GateMasqSelCtMark, the plain
// one otherwise, each for IPv4 and IPv6.
func (c *Compiler) gateDeliverRules() []string {
	mask := GateCtMark | GateMasqSelCtMark
	local := "meta mark set meta mark | " + hexMark(GateLocalPktMark) + " accept"
	var out []string
	for _, l := range []struct {
		value uint32
		port  uint16
	}{{mask, c.GateMasqPort}, {GateCtMark, c.GatePlainPort}} {
		match := "meta l4proto tcp " + ctMarkMatch(mask, l.value)
		out = append(out,
			fmt.Sprintf("%s tproxy ip to 127.0.0.1:%d %s", match, l.port, local),
			fmt.Sprintf("%s tproxy ip6 to [::1]:%d %s", match, l.port, local))
	}
	return out
}

// writeGateICSChain emits gateICSChain: a selected connection with an
// endpoint on an ICS device or address is ungated and returns. Under a
// refusing admission it then passes as a plain connection, unscanned,
// instead of being reset.
func writeGateICSChain(buf *bytes.Buffer, gate rules.GateSelection) error {
	buf.WriteString("  chain " + gateICSChain + " {\n")
	ungate := ungateStmt() + " return"
	if len(gate.ICSDevices) > 0 {
		set, err := ifnameSet(gate.ICSDevices)
		if err != nil {
			return fmt.Errorf("gate ICS devices: %w", err)
		}
		buf.WriteString("    iifname " + set + " " + ungate + ";\n")
		buf.WriteString("    fib daddr oifname " + set + " " + ungate + ";\n")
	}
	families, err := splitFamilies(gate.ICSCIDRs)
	if err != nil {
		return fmt.Errorf("gate ICS addresses: %w", err)
	}
	for f, ip := range familyKeyword {
		if len(families[f]) == 0 {
			continue
		}
		set := "{ " + strings.Join(families[f], ", ") + " }"
		buf.WriteString("    " + ip + " saddr " + set + " " + ungate + ";\n")
		buf.WriteString("    " + ip + " daddr " + set + " " + ungate + ";\n")
	}
	buf.WriteString("  }\n")
	return nil
}

// writeGateAdmitChain emits GateAdmitChain in the state of c.GateAdmit.
func (c *Compiler) writeGateAdmitChain(buf *bytes.Buffer) {
	buf.WriteString("  chain " + GateAdmitChain + " {\n")
	for _, rule := range gateAdmitRules(c.GateAdmit) {
		buf.WriteString("    " + rule + ";\n")
	}
	buf.WriteString("  }\n")
}

// gateAdmitRules returns GateAdmitChain's rules for an admission state.
// Open delivers the connection; when TPROXY cannot (no listener) the chain
// ends and GatePreChain resets the connection. Pass ungates the connection
// and returns. Refuse, the zero value and every unknown state, lets an ICS
// endpoint pass ungated and resets the rest.
func gateAdmitRules(state GateAdmitState) []string {
	switch state {
	case GateAdmitOpen:
		return []string{"jump " + GateDeliverChain}
	case GateAdmitPass:
		return []string{ungateStmt() + " return"}
	}
	return []string{"jump " + gateICSChain, ctMarkMatch(GateCtMark, GateCtMark) + " " + rejectTCP}
}

// GateAdmitSwitch returns the nft script that sets the admission state of
// an installed ruleset: one transaction that flushes GateAdmitChain and
// adds the rules of the state. Apply it only to a ruleset compiled by a
// compiler that SteersGate.
func (c *Compiler) GateAdmitSwitch(state GateAdmitState) string {
	table := c.policyTable()
	var b strings.Builder
	fmt.Fprintf(&b, "flush chain inet %s %s\n", table, GateAdmitChain)
	for _, rule := range gateAdmitRules(state) {
		fmt.Fprintf(&b, "add rule inet %s %s %s\n", table, GateAdmitChain, rule)
	}
	return b.String()
}

// writeGatePreChain emits GatePreChain on the prerouting hook after DNAT.
// Loopback and locally addressed packets, management included, return
// untouched before anything is selected; selecting is left out of a
// ruleset whose selection is off.
func (c *Compiler) writeGatePreChain(buf *bytes.Buffer, selecting bool) {
	buf.WriteString("  chain " + GatePreChain + " {\n")
	buf.WriteString("    type filter hook prerouting priority -90;\n")
	buf.WriteString("    policy accept;\n")
	buf.WriteString("    iifname \"lo\" return;\n")
	buf.WriteString("    " + ctMarkMatch(GateUpstreamCtMark, GateUpstreamCtMark) + " ct direction reply meta mark set meta mark | " + hexMark(GateLocalPktMark) + " accept;\n")
	buf.WriteString("    fib daddr type local return;\n")
	buf.WriteString("    " + ctMarkMatch(GateCtMark, GateCtMark) + " jump " + GateDeliverChain + ";\n")
	if selecting {
		buf.WriteString("    ct state new tcp flags & (fin | syn | rst | ack) == syn jump " + gateSelectChain + ";\n")
	}
	buf.WriteString("    " + ctMarkMatch(GateCtMark, GateCtMark) + " " + rejectTCP + ";\n")
	buf.WriteString("  }\n")
}

// writeGateOutputChains emits the policy output chain, which sends the
// replies of gated connections to GateReplyChain, and GateOutputMarkChain,
// which marks the gate's upstream connections from their sockets' mark
// before connection tracking confirms them.
func (c *Compiler) writeGateOutputChains(buf *bytes.Buffer) {
	buf.WriteString("  chain output {\n")
	buf.WriteString("    type filter hook output priority 0;\n")
	buf.WriteString("    policy accept;\n")
	buf.WriteString("    " + ctMarkMatch(GateCtMark, GateCtMark) + " ct direction reply goto " + GateReplyChain + ";\n")
	buf.WriteString("  }\n")
	buf.WriteString("  chain " + GateOutputMarkChain + " {\n")
	buf.WriteString("    type filter hook output priority -150;\n")
	buf.WriteString("    policy accept;\n")
	buf.WriteString("    " + pktMarkMatch(GateUpstreamSockMark, GateUpstreamSockMark) + " " + ctMarkSet(GateUpstreamCtMark) + ";\n")
	buf.WriteString("  }\n")
}

// gateUpstreamMasquerade masquerades the gate's upstream connections whose
// clients were accepted on the masquerading listener, by the socket mark
// the gate sets on them.
func gateUpstreamMasquerade() string {
	mask := GateUpstreamSockMark | GateMasqSockMark
	return pktMarkMatch(mask, mask) + " masquerade"
}

// gateBlockRules returns the temporary block checks of the dynamic table's
// input and output chains: the forward chain's checks scoped to gated
// connections on input and to the gate's upstream sockets on output, so a
// block of a lab host never touches that host's management session.
func gateBlockRules() map[string][]string {
	out := map[string][]string{}
	for _, scope := range []struct{ chain, match string }{
		{"input", ctMarkMatch(GateCtMark, GateCtMark)},
		{"output", pktMarkMatch(GateUpstreamSockMark, GateUpstreamSockMark)},
	} {
		for _, rule := range blockRules() {
			out[scope.chain] = append(out[scope.chain], scope.match+" "+rule)
		}
	}
	return out
}

// gateDevices quotes device names as an nft set, sorted; "" for none.
func gateDevices(devices []string) (string, error) {
	if len(devices) == 0 {
		return "", nil
	}
	return ifnameSet(devices)
}

// gatePortSet renders port ranges, merged and sorted by the control plane,
// as an nft set.
func gatePortSet(ranges []rules.GatePortRange) string {
	parts := make([]string, 0, len(ranges))
	for _, r := range ranges {
		if r.Lo == r.Hi {
			parts = append(parts, fmt.Sprint(r.Lo))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", r.Lo, r.Hi))
		}
	}
	return "{ " + strings.Join(parts, ", ") + " }"
}
