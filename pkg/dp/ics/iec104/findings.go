// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package iec104

import (
	"fmt"
	"slices"

	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

// Conformance finding codes (eventfields.KeyConformance) of content inside
// an APDU whose length octet framed it. A finding never replaces decoded
// fields: what the decoder read stays on the event, what it could not read
// stays absent. Bytes that cannot start an APDU are a *dpi.FrameError, not
// a finding: the frame boundary is lost.
const (
	// FindingReservedBits: a reserved control-field bit or octet is set
	// (IEC 60870-5-104 clause 5). The sequence numbers or U function the
	// octets carry are still read.
	FindingReservedBits = "iec104.reserved_bits"
	// FindingUFunction: U-format control octet 1 does not hold exactly
	// one of STARTDT, STOPDT and TESTFR act or con; u_function is absent.
	FindingUFunction = "iec104.u_function"
	// FindingAPCILength: an S- or U-format APDU whose length is not 4.
	FindingAPCILength = "iec104.apci_length"
	// FindingShortASDU: an I-format APDU whose ASDU is shorter than the
	// 6-octet data unit identifier; type ID, COT and CA are absent.
	FindingShortASDU = "iec104.short_asdu"
	// FindingUnsupportedType: the type ID is read but has no decoder
	// descriptor; the objects are not decoded.
	FindingUnsupportedType = "iec104.unsupported_type"
	// FindingRole: the client sent a monitor-direction type (1..44) or the
	// server sent a control or system type with cause 6 or 8.
	FindingRole = "iec104.role"
	// FindingZeroObjects: VSQ names zero information objects.
	FindingZeroObjects = "iec104.zero_objects"
	// FindingProfileSQ: the SQ bit or object count violates the decoder
	// profile (control and system types need SQ=0 and one object; SQ=1
	// only on untimed monitor types).
	FindingProfileSQ = "iec104.profile_sq"
	// FindingBodyLength: the ASDU body does not hold exactly the objects
	// VSQ and the type's element size require.
	FindingBodyLength = "iec104.body_length"
	// FindingIOARange: an SQ=1 object sequence overflows the 24-bit IOA.
	FindingIOARange = "iec104.ioa_range"
	// FindingElement: an information element holds a value the standard
	// does not define (SCO reserved bit, DCS/RCS 0 or 3).
	FindingElement = "iec104.element"
	// FindingTime: a CP56Time2a field is out of range or names a date that
	// cannot exist.
	FindingTime = "iec104.time"
)

// Findings lists every code the decoder can emit, sorted, for exhaustive
// tests and documentation.
var Findings = []string{
	FindingAPCILength, FindingBodyLength, FindingElement, FindingIOARange,
	FindingProfileSQ, FindingReservedBits, FindingRole, FindingShortASDU,
	FindingTime, FindingUFunction, FindingUnsupportedType, FindingZeroObjects,
}

// addFinding records code on attrs, keeping the list sorted and unique.
func addFinding(attrs map[string]any, code string) {
	codes, _ := eventfields.Strings(attrs, eventfields.KeyConformance)
	if i, found := slices.BinarySearch(codes, code); !found {
		codes = slices.Insert(codes, i, code)
	}
	attrs[eventfields.KeyConformance] = codes
}

// conformanceError is a decoder error together with the finding code that
// names it on the event.
type conformanceError struct {
	code string
	msg  string
}

func (e *conformanceError) Error() string { return e.msg }

// findingError builds the error of one finding.
func findingError(code, format string, args ...any) error {
	return &conformanceError{code: code, msg: fmt.Sprintf(format, args...)}
}

// profileError marks a decoder profile restriction: the standard allows
// it, but containd rejects it.
func profileError(code, format string, args ...any) error {
	return findingError(code, "profile: "+format, args...)
}
