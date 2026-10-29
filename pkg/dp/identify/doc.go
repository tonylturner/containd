// SPDX-License-Identifier: Apache-2.0

// Package identify provides bounded, passive protocol evidence, not policy or
// decoder events. A Table belongs to one serialized caller; it is not concurrent.
//
// The caller opens an opaque Key for each connection incarnation, then observes
// both TCP SYN directions and subsequent payload arrivals. Missing SYN coverage
// is explicit; no offset scanning is performed. For UDP, each Arrival is one
// entire datagram. Poll applies the injected ingestion clock's deadline when
// traffic is idle. Close, tuple reuse and reconfiguration require Release.
//
// A unique confirmed Decision can bind a decoder, but never authorizes traffic.
// Expected records registry port expectations independently of content identity.
// Ambiguous and candidate decisions remain pending until stronger evidence or
// budget exhaustion. Unknown protocol layouts are not confirmation evidence.
//
// Take transfers retained storage once, and leaves terminal metadata cached
// until Release. Do not submit the triggering arrival a second time: it is
// already in Replay. Replay.Bytes are contiguous directional TCP prefixes;
// Replay.Sequence and Replay.Pending preserve origins and out-of-order bytes for
// the caller's bound stream reassembler. For UDP, replay each Datagram boundary
// independently. An incomplete decision's replay may contain gaps; it is not a
// successful decoder binding.
//
// Admission charges retained backing-array capacities plus EntryCharge, not
// just logical payload lengths. Terminal entries also consume the entry cap.
// Transient probe-reader allocations, Go map bucket overhead beyond the fixed
// allowance, caller-owned replay and bound decoder storage are not a process
// heap limit. Overflow refuses new work; it never evicts another decision.
package identify
