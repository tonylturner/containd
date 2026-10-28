// SPDX-License-Identifier: Apache-2.0
// Package cip inspects EtherNet/IP explicit messaging and bare UDP I/O CPF.
//
// Conformance codes describe wire violations: cip.unknown_command,
// cip.encapsulation_length (UDP boundary differs from the declared length),
// cip.cpf_layout (item framing, interface or address length), cip.item_truncated,
// cip.message_short, cip.epath_truncated, cip.msp_layout (invalid table intervals),
// cip.response_reserved (nonzero response reserved byte), and
// cip.msp_response_mismatch (child response bit differs from its wrapper).
//
// Undecoded codes describe unwalked protocol structure: cip.msp_limit (shared
// 32-child budget), cip.msp_nesting (eight envelope levels),
// cip.epath_unsupported (unknown segment format), cip.extra_data_item (only the
// first explicit data item is selected), cip.cpf_item_unsupported (unknown item
// type ID), and cip.encapsulation_payload_unsupported (body of an unknown
// encapsulation command, whose message layout cannot be established).
// Codes are sorted and unique on events. They are not wire violations.
//
// Service-specific values and parameters are data after a decoded service and
// path, not unwalked protocol identity. Known non-explicit encapsulation bodies,
// encapsulation error bodies and known CPF metadata items are also data.
// They do not cause undecoded findings; MSP children and paths still must be
// walked, and a second explicit data item still reports uninspected content.
//
// UDP I/O assembly bytes are opaque application data, not undecoded protocol.
// Their preview is bounded to 512 bytes; data_length always retains the full
// length. No transport class or assembly meaning is inferred without connection
// state. Connected explicit sequences are separate from I/O address sequences.
package cip
