// SPDX-License-Identifier: Apache-2.0

// Package modbus decodes Modbus/TCP ADUs, retaining readable fields even when
// a frame carries conformance findings:
//
//   - modbus.pid_nonzero: nonzero MBAP protocol identifier.
//   - modbus.request_exception: exception sent in the connection's request direction.
//   - modbus.pdu_layout: a known directional PDU layout or diagnostics data rule failed.
//   - modbus.quantity_range: a decoded data-access quantity exceeds its function's limits.
//
// Framed FC8 diagnostics outside the serial-line subfunction profile carry
// undecoded code modbus.diagnostics_subfunction. Unknown names and data rules
// are not silently treated as supported. FC8 subfunctions 1, 3, 4, 10 and 20
// mutate device state; the other supported diagnostics are reads. A normal
// force-listen-only response is nonconformant: the specified operation has
// no normal reply. TCP stacks need not implement serial-port behavior.
//
// Exceptions retain their function code and exception identity, but have no
// subfunction on the wire. This stateless decoder does not correlate requests
// to invent an FC8 exception's write category or subfunction.
package modbus
