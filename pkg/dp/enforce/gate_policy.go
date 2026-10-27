// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"bytes"
	"fmt"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// A gated connection never traverses the forward chain: the gate accepts
// its client leg locally and answers it from this namespace. The firewall
// policy still decides it, by the forward chain's decision graph lowered
// twice more (zoneLowering):
//
//   - GateInputChain, entered from the input chain for the original
//     direction (client to gate), is the whole graph: meters, queued ICS
//     rules, the conditional recheck, the established accept, port forward
//     grants, TAG counts and the deciding rules, then the snapshot's
//     default as an explicit verdict, since a regular chain has no policy.
//   - GateReplyChain, entered from the output chain for the reply direction
//     (gate to client), is what the forward chain applies to replies: the
//     meters' reply lines and the conditional recheck, then accept, as the
//     established accept would. A reset the kernel generates for a gated
//     connection, by a RESET rule or a refused selection, travels this way
//     with the connection's conntrack; it passes first, as it passes the
//     revocations chain, so a RESET recheck never rejects its own reset.
//
// Egress zones come from the connection mark, where selection recorded the
// routing decision for the first SYN; ingress zones from the input
// interface on the original direction and the output interface on
// replies. Counters, logs and queues are the forward chain's own.

// writeGateInputChain emits GateInputChain.
func (c *Compiler) writeGateInputChain(buf *bytes.Buffer, snap *rules.Snapshot, preds *predicates) error {
	buf.WriteString("  chain " + GateInputChain + " {\n")
	if err := c.writeDecisions(buf, snap, preds, targetGateInput); err != nil {
		return err
	}
	buf.WriteString(fmt.Sprintf("    %s;\n", defaultPolicy(snap.Default)))
	buf.WriteString("  }\n")
	return nil
}

// writeGateReplyChain emits GateReplyChain.
func (c *Compiler) writeGateReplyChain(buf *bytes.Buffer, snap *rules.Snapshot, preds *predicates) error {
	buf.WriteString("  chain " + GateReplyChain + " {\n")
	buf.WriteString("    tcp flags & rst == rst accept;\n")
	meters, _, _ := forwardSections(snap.Firewall)
	if err := c.writeEntries(buf, preds, targetGateReply, meters); err != nil {
		return err
	}
	preds.writeRecheckJump(buf, targetGateReply)
	buf.WriteString("    accept;\n")
	buf.WriteString("  }\n")
	return nil
}
