// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"bytes"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// Gated client packets and replies use the forward policy graph with its
// missing interface coordinate supplied by the recorded stable gate zone.
// Only locally generated TCP resets escape rematching on the reply path.

// writeGateInputChain emits GateInputChain.
func (c *Compiler) writeGateInputChain(buf *bytes.Buffer, snap *rules.Snapshot, preds *predicates) error {
	buf.WriteString("  chain " + GateInputChain + " {\n")
	if err := c.writeDecisions(buf, snap, preds, targetGateInput); err != nil {
		return err
	}
	buf.WriteString("  }\n")
	return nil
}

// writeGateReplyChain emits GateReplyChain.
func (c *Compiler) writeGateReplyChain(buf *bytes.Buffer, snap *rules.Snapshot, preds *predicates) error {
	buf.WriteString("  chain " + GateReplyChain + " {\n")
	buf.WriteString("    tcp flags & rst == rst accept;\n")
	if err := c.writeDecisions(buf, snap, preds, targetGateReply); err != nil {
		return err
	}
	buf.WriteString("  }\n")
	return nil
}
