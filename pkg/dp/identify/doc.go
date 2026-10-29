// SPDX-License-Identifier: Apache-2.0

// Package identify provides bounded, passive protocol evidence, not policy or
// decoder events. A Table belongs to one serialized caller; it is not concurrent.
//
// The caller opens an opaque Key for each connection incarnation, then observes
// both TCP SYN directions and subsequent payload arrivals. Missing SYN coverage
// is explicit; no offset scanning is performed. For UDP, each Arrival is one
// entire datagram. Poll or Sweep applies deadlines when traffic is idle: from
// Open for SYN-only entries, and from first payload thereafter. Sweep returns
// newly expired keys; callers Release them after consuming timeout decisions.
// Close/EOF uses Finish before Release; tuple reuse and reconfiguration also
// require Release.
//
// A unique confirmed Decision can bind a decoder, but never authorizes traffic.
// Expected records registry port expectations independently of content identity.
// Ambiguous and candidate decisions remain pending until stronger evidence or
// budget exhaustion. Unknown protocol layouts are not confirmation evidence.
// Result.States exposes directional evidence; a hard reject in either observed
// direction prevents confirmation from the other alone. Modbus, IEC and ENIP
// walk validated frame boundaries, including neutral ENIP NOPs, without offset
// scanning. ENIP over UDP supports List commands and NOP only. IEC control
// functions do not establish client/server roles; callers use TCP SYN metadata.
//
// Take transfers retained storage once, and leaves terminal metadata cached
// until Release. For a confirmation the entire triggering payload is already
// in Replay; never submit it twice. Replay.TriggerRetained makes failed admission explicit:
// deadline, truncation, missing SYN, conflict and allocation refusal can end an
// entry without retaining the triggering payload; clipping retains only its
// admitted prefix. None of those outcomes can bind a decoder. Replay.Bytes
// are contiguous directional TCP prefixes;
// Replay.Sequence and Replay.Pending preserve origins and out-of-order bytes for
// the caller's bound stream reassembler. For UDP, replay each Datagram boundary
// independently. Oversized arrivals retain only their budgeted prefix for a
// rejection pass; they can never confirm. Datagram.Length preserves the original
// UDP boundary even when clipped. An incomplete decision's replay may contain
// gaps or clipped bytes; it is not a successful decoder binding.
//
// Admission charges retained backing-array capacities plus EntryCharge, not
// just logical payload lengths. Terminal entries also consume the entry cap.
// Transient probe-reader allocations, Go map bucket overhead beyond the fixed
// allowance, caller-owned replay and bound decoder storage are not a process
// heap limit. Overflow refuses new work; it never evicts another decision.
package identify
