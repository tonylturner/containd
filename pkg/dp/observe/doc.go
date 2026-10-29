// SPDX-License-Identifier: Apache-2.0

// Package observe owns passive protocol identification and observation decoding.
// It never returns a verdict. New requires a dedicated dpi.NewObservationManager
// with fresh enabled decoders. Open admits an opaque incarnation key (live
// connection key or offline run/serial); Observe never implicitly opens a key.
//
// Lock order is caller flow lock, Observer mutex, manager stream locks. The
// LegacyDecodes and Scope callbacks run under the mutex and must take no locks.
// LegacyDecodes is the sole binding policy: it can suppress standard-port
// matches, mismatches or any other caller-owned legacy decoding without changing
// core logic. Scope is a caller-owned immutable rule snapshot, never evaluated
// here. The clock is injected for deadlines; Packet.At is capture/event time.
//
// A unique confirmation transfers retained evidence once. Replay follows capture
// arrival order with original direction/state/time; overlapping and pending TCP
// ranges pass through session reassembly, so a decoder consumes each byte once.
// Session ids and SYN roles are frozen, including across key adoption. Each TCP
// direction needs its own SYN before its payload can be decoded. UDP remains
// whole datagrams, including ENIP encapsulation on 2222; implicit I/O is legacy.
//
// FIN payload is observed first. The first FIN keeps the peer stream; both FINs
// or RST end the binding once. Finish handles close/EOF and keeps a terminal
// marker. Release removes the incarnation marker only when the owning flow is
// retired. Trailing ACKs cannot reopen markers. At marker capacity Open refuses
// admission; Observe on refused keys does no work. Callers must not repeatedly
// retry admission for a refused incarnation. Drain finalizes pending evidence,
// ends all streams, clears markers and permanently closes this observer, so
// concurrent traffic cannot resurrect it during reconfiguration.
package observe
