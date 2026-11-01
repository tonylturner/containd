// SPDX-License-Identifier: Apache-2.0

package engine

import "testing"

func TestIEC104HealthReasonCodes(t *testing.T) {
	for _, code := range []IEC104EnforcementReason{
		IEC104ReasonQueue, IEC104ReasonVerdict, IEC104ReasonReset,
		IEC104ReasonInjector, IEC104ReasonWorker, IEC104ReasonFraming,
		IEC104ReasonEnvelope, IEC104ReasonSteering, IEC104ReasonAdmission,
		IEC104ReasonGateZones, IEC104ReasonAddresses,
	} {
		t.Run(string(code), func(t *testing.T) {
			h := newIECHealth(nil)
			h.setActive(true)
			h.fault(string(code), "private diagnostic")
			st := h.status()
			if st.Healthy || !st.Active || st.ReasonCode != code || st.Reason != "private diagnostic" {
				t.Fatalf("fault category lost: %+v", st)
			}
			h.clear(string(code))
			if st := h.status(); !st.Healthy || st.ReasonCode != "" || st.Reason != "" {
				t.Fatalf("recovery retained fault: %+v", st)
			}
		})
	}
	h := newIECHealth(nil)
	h.setICS(true)
	h.fault(faultReset, "another protocol reset failed")
	if st := h.status(); st.Active || st.Healthy || st.ReasonCode != IEC104ReasonReset {
		t.Fatalf("non-IEC reset category lost: %+v", st)
	}
	h.setActive(true)
	h.fault(faultInjector, "injector down")
	h.fault(faultQueue, "queue bind down")
	for range 10 {
		if st := h.status(); st.ReasonCode != IEC104ReasonQueue {
			t.Fatalf("unstable fault priority: %+v", st)
		}
	}
	h.fault(faultAdmission, "admission cleanup down")
	if st := h.status(); st.ReasonCode != IEC104ReasonAdmission {
		t.Fatalf("global fault must precede IEC readiness: %+v", st)
	}
}
