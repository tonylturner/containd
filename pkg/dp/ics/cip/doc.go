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
// Undecoded codes describe framed content not inspected: cip.msp_limit (shared
// 32-child budget), cip.msp_nesting (eight envelope levels),
// cip.epath_unsupported (unknown segment format), cip.extra_data_item (only the
// first explicit data item is selected), cip.cpf_item_unsupported (unknown item
// body), cip.service_payload_unsupported (service-specific body has no parser),
// and cip.encapsulation_payload_unsupported (non-explicit command body).
// Codes are sorted and unique on events. They are not wire violations.
//
// UDP I/O assembly bytes are opaque application data, not undecoded protocol.
// Their preview is bounded to 512 bytes; data_length always retains the full
// length. No transport class or assembly meaning is inferred without connection
// state. Connected explicit sequences are separate from I/O address sequences.
package cip
