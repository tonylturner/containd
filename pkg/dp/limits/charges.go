// SPDX-License-Identifier: Apache-2.0

package limits

// Fixed metadata credits cover entry bookkeeping, independently of variable
// backing allocations. Owners additionally charge every retained backing
// allocation's capacity and any owned variable-length keys. These credits are
// accounting policy, not a measurement or bound of Go allocator/process memory.
const (
	StreamMetadataBytes      int64 = 512
	BindingMetadataBytes     int64 = 1024
	DecoderMetadataBytes     int64 = 1024
	DNP3StationMetadataBytes int64 = 1024
	IECSessionMetadataBytes  int64 = 4096
	HeldTokenMetadataBytes   int64 = 512
	PairingMetadataBytes     int64 = 256

	// HeldPacketHeaderAllowanceBytes is the fixed conservative header
	// allowance used when charging a held packet: payload length plus this
	// allowance plus HeldTokenMetadataBytes. It is an accounting convention;
	// it does not measure captured headers or kernel skb residency.
	HeldPacketHeaderAllowanceBytes int64 = 256
)
