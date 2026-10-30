// SPDX-License-Identifier: Apache-2.0

package identify

import "github.com/tonylturner/containd/pkg/dp/ics/iec104"

func iecEvidence(b []byte) evidence {
	e := pending(b)
	var previous iec104.APDUValidation
	for offset := 0; offset < len(b); {
		if b[offset] != 0x68 {
			return invalid(b[:offset+1])
		}
		v, err := iec104.ValidateAPDU(b[offset:])
		if err != nil {
			return invalid(b)
		}
		if v.Size == 0 {
			break
		}
		if e.state == NeedMore {
			e.state, e.why = Candidate, "single APDU"
		}
		if !v.Supported {
			e.why = "unsupported ASDU profile"
		} else {
			if previous.Supported && (previous.Format != "S" || v.Format != "S") {
				e.state, e.why = Confirmed, "consecutive APDUs"
			}
			switch v.UFunction {
			case "startdt_act":
				e.uAct |= 1
			case "startdt_con":
				e.uCon |= 1
			case "stopdt_act":
				e.uAct |= 2
			case "stopdt_con":
				e.uCon |= 2
			case "testfr_act":
				e.uAct |= 4
			case "testfr_con":
				e.uCon |= 4
			}
		}
		previous = v
		offset += v.Size
	}
	return e
}
