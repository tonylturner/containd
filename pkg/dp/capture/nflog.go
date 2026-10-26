// SPDX-License-Identifier: Apache-2.0

package capture

import (
	"github.com/tonylturner/containd/pkg/dp/events"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// RuleHitSink receives the firewall.rule.hit events of packets the kernel
// logs to the nflog group (StartNFLog). key is the logged packet's
// connection key: its wire tuple, with Dir DirReverse when conntrack saw
// the packet in the reply direction. It is nil when the packet's tuple did
// not decode.
type RuleHitSink interface {
	RuleHit(ev events.Event, key *flow.Key)
}
