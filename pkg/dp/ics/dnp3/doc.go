// SPDX-License-Identifier: Apache-2.0

// Package dnp3 inspects IEEE 1815 link frames and independently decodes each
// transport-completed application fragment. It does not hold back earlier TCP
// packets or promise atomic whole-response prevention. Typed point predicates
// are not implemented; objects and CROBs are evidence only.
//
// Assemblies are keyed by stream session, TCP direction, ordered link addresses
// and link DIR. StreamEnded releases that direction. ParseStream prunes on an
// injectable clock: 30 seconds idle, 60 seconds absolute per incomplete
// transport/application assembly. Pruning/end produce no asynchronous events;
// a later continuation is an orphan. No timers or goroutines are used.
//
// Inspection bounds (not IEEE limits) are 64 KiB application bytes, 1024 link
// segments per fragment, 1024 application fragments per response, 4096 station
// contexts and 16 MiB retained storage including payload, duplicate bytes,
// provenance and conservative context metadata charges. A decoded object header
// has at most 8192 point records; header-only ranges remain compact. Overflow
// releases the affected assembly, never another live station. No joining resumes
// until FIR. Physical frames keep their own ranges; link_ranges on the finishing
// frame identifies the constituent link frames. raw_hex is that physical frame,
// never synthesized application bytes. Application headers and IIN are not
// concatenated across application fragments.
//
// Identical last transport segments are reported and not appended. Confirmed
// link retries use FCV/FCB plus exact bytes; conflicting retries abort transport.
// Unconfirmed new FIR+FIN requests are not deduplicated by sequence or content.
// Application response duplicates retain a bounded fingerprint and do not
// advance the response summary. Solicited/unsolicited channels are independent.
// Confirmations correlate only when both directions share a session identity;
// legacy directional flow hashes cannot prove a peer and are never guessed.
//
// Conformance codes (tolerant policy retains decoded evidence):
//
//   - dnp3.data_crc: one or more data-block CRCs disagree; header CRC failures
//     instead produce FrameError. A bad CRC is also retained until completion.
//   - dnp3.application_header: a completed fragment has a short application/IIN header.
//   - dnp3.object_walk: truncated complete-fragment objects or an illegal qualifier/range.
//   - dnp3.crob_value: reserved operation, trip/close or command-status encoding.
//   - dnp3.link_duplicate, dnp3.link_retry_conflict: confirmed link retry evidence.
//   - dnp3.transport_duplicate, dnp3.transport_conflict: repeated last sequence
//     with identical/different bytes, respectively.
//   - dnp3.transport_orphan, dnp3.transport_sequence, dnp3.transport_restart:
//     missing FIR, sequence gap, or FIR interrupting pending transport bytes.
//   - dnp3.application_control: invalid control bits or UNS/function disagreement.
//   - dnp3.application_duplicate, dnp3.application_sequence,
//     dnp3.application_restart: response retry, missing/out-of-sequence fragment,
//     or FIR interrupting an unfinished response.
//
// Undecoded codes (framed bytes not inspected, distinct from wire illegality):
//
//   - dnp3.link_payload: payload on an unsupported link function.
//   - dnp3.transport_incomplete: abandoned/orphaned transport bytes.
//   - dnp3.application_incomplete: short header or incomplete response sequence.
//   - dnp3.assembly_limit: fragment byte/segment or response-fragment bound.
//   - dnp3.assembly_budget: station-count or aggregate retained-storage budget.
//   - dnp3.object_limit: point-record inspection bound.
//   - dnp3.object_qualifier: object tail after an illegal qualifier/range.
//   - dnp3.object_truncated: incomplete object header/index/value.
//   - dnp3.object_unsupported: unknown object value layout. Never scan unknown
//     values for guessed headers. Group 12 variation 2 is not a CROB.
//
// Object records include readable presence flags, original qualifier/range,
// byte offset/covered prefix, variation and associated point indices. A missing
// index is distinct from zero; virtual/all-object/count-only addressing never
// fabricates an index. CROBs preserve raw control, operation, queue/clear,
// trip/close, repeat count, on/off milliseconds and response status.
package dnp3
