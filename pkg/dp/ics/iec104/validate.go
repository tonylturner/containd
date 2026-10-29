// SPDX-License-Identifier: Apache-2.0

package iec104

import "fmt"

// APDUValidation describes the first APDU without emitting events or touching
// decoder state. Size zero with no error means more bytes are needed.
type APDUValidation struct {
	Size      int
	Format    string
	UFunction string
	// Supported is false for unknown or profile-restricted ASDUs. Their
	// identity remains uncertain, rather than treating them as another protocol.
	Supported bool
}

// ValidateAPDU validates APCI and, for supported I-format types, the ASDU using
// the decoder's readers. Bytes after the first APDU are ignored. Sender roles
// are deliberately not inferred from control functions or port numbers.
func ValidateAPDU(b []byte) (APDUValidation, error) {
	n, err := frameAPDU(b)
	if err != nil || n == 0 {
		return APDUValidation{}, err
	}
	a := decodeAPCI(b[:n])
	v := APDUValidation{Size: n, Format: a.format, UFunction: a.uFunction}
	if len(a.findings) != 0 {
		return v, fmt.Errorf("invalid APCI: %v", a.findings)
	}
	if a.format != "I" {
		if a.length != 4 {
			return v, fmt.Errorf("%s-format length %d, want 4", a.format, a.length)
		}
		v.Supported = true
		return v, nil
	}
	asdu := b[apciLen:n]
	if len(asdu) < asduHeaderLen {
		return v, fmt.Errorf("short ASDU")
	}
	h := decodeASDUHeader(asdu)
	if h.typeID == 0 || h.cause == 0 || h.count == 0 {
		return v, fmt.Errorf("invalid ASDU header")
	}
	d, ok := descriptors[h.typeID]
	if !ok || checkProfile(h, d) != nil {
		return v, nil
	}
	if _, err := decodeObjects(h, d, asdu[asduHeaderLen:]); err != nil {
		return v, err
	}
	v.Supported = true
	return v, nil
}
