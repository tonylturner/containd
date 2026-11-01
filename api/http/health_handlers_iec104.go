// SPDX-License-Identifier: Apache-2.0

package httpapi

import dpengine "github.com/tonylturner/containd/pkg/dp/engine"

// publicIEC104Health preserves the public shape without exposing raw engine
// diagnostics or unknown reason-code values. No text matching crosses this
// unauthenticated boundary.
func publicIEC104Health(st dpengine.IEC104Enforcement) dpengine.IEC104Enforcement {
	code := st.ReasonCode
	st.ReasonCode = ""
	st.Reason = ""
	if st.Healthy {
		return st
	}
	switch code {
	case dpengine.IEC104ReasonQueue:
		st.Reason = "IEC104 queue bind/receive failure"
	case dpengine.IEC104ReasonInjector:
		st.Reason = "IEC104 reset injector unavailable"
	case dpengine.IEC104ReasonReset:
		st.Reason = "IEC104 reset failure"
		if !st.Active {
			st.Reason = "ICS mid-stream reset failure"
		}
	case dpengine.IEC104ReasonVerdict:
		st.Reason = "IEC104 queue verdict failure"
	case dpengine.IEC104ReasonWorker:
		st.Reason = "IEC104 packet worker failure"
	case dpengine.IEC104ReasonFraming:
		st.Reason = "IEC104 stream framing failure"
	case dpengine.IEC104ReasonEnvelope:
		st.Reason = "IEC104 steering/envelope disagreement"
	case dpengine.IEC104ReasonSteering:
		st.Reason = "IEC104 steering unavailable"
	case dpengine.IEC104ReasonAdmission:
		st.Reason = "dataplane admission cleanup failure"
	case dpengine.IEC104ReasonGateZones:
		st.Reason = "dataplane zone cleanup failure"
	case dpengine.IEC104ReasonAddresses:
		st.Reason = "dataplane local address refresh failure"
	default:
		st.Reason = "IEC104 enforcement unavailable"
	}
	return st
}
