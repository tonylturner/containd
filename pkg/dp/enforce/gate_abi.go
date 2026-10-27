// SPDX-License-Identifier: Apache-2.0

package enforce

// Scanning gate steering ABI. The compiler's nft lowering, the engine's
// admission switch and the gate's transparent sockets share these values; a
// change here changes all three. Mark writes are always masked, so the
// NFQUEUE bits (QueueMarkMask) and other users of the marks are untouched.
const (
	// GateCtMark is set in the connection mark of a gated connection when
	// its first SYN is selected; it stays for the connection's lifetime.
	GateCtMark uint32 = 0x00100000
	// GateUpstreamCtMark is set in the connection mark of the gate's own
	// upstream connection (copied from GateUpstreamSockMark on output).
	GateUpstreamCtMark uint32 = 0x00200000
	// GateMasqSelCtMark is set at selection when the connection would be
	// masqueraded without the gate; it picks the masquerading listener.
	GateMasqSelCtMark uint32 = 0x00020000
	// GateZoneCtMask holds the egress zone index (1-255) of a gated
	// connection, shifted by GateZoneCtShift.
	GateZoneCtMask uint32 = 0x0000ff00

	// GateLocalPktMark routes a packet to the local stack (policy routing
	// rule in pkg/dp/netcfg, which carries the same value).
	GateLocalPktMark uint32 = 0x00400000
	// GateUpstreamSockMark is the SO_MARK of every gate upstream socket.
	GateUpstreamSockMark uint32 = 0x00800000
	// GateMasqSockMark is added to the SO_MARK of an upstream socket whose
	// client was accepted on the masquerading listener.
	GateMasqSockMark uint32 = 0x00010000
)

// GateZoneCtShift positions the egress zone index in GateZoneCtMask.
const GateZoneCtShift uint = 8

// Gate chain names in the policy table.
const (
	GatePreChain        = "gate_pre"       // prerouting -90: selection and delivery
	GateOutputMarkChain = "gate_out"       // output -150: upstream ct mark
	GateDeliverChain    = "gate_deliver"   // tproxy to the listeners
	GateAdmitChain      = "gate_admit"     // switched by the engine
	GateInputChain      = "gate_in"        // policy for client→gate (original direction)
	GateReplyChain      = "gate_out_reply" // policy for gate→client (reply direction)
)

// GateAdmitState is the admission state of new gated connections.
type GateAdmitState uint8

const (
	// GateAdmitRefuse resets new gated connections, except those with an
	// ICS endpoint, which pass ungated. It is the initial state of the
	// kernel switch and the state for a closed fail policy while the
	// listeners or their routing are down.
	GateAdmitRefuse GateAdmitState = iota
	// GateAdmitOpen delivers new gated connections to the listeners.
	GateAdmitOpen
	// GateAdmitPass lets new selected connections through ungated: an open
	// fail policy while the listeners or their routing are down.
	GateAdmitPass
)
