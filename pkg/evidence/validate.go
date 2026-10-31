// SPDX-License-Identifier: Apache-2.0

package evidence

import "fmt"

// ValidateEnvelope checks normalized structure only, not trust, representability
// or conformance. Malformed/partial observations remain valid evidence; adapters
// must mark Quality rather than discard findings to pass this check.
func (o Observation) ValidateEnvelope() error {
	if o.SchemaVersion != SchemaVersion || o.DatasetID == "" || o.ConnectionID == "" || o.ParentID == "" || o.CapturedAt.IsZero() {
		return fmt.Errorf("missing or unsupported observation envelope")
	}
	if o.Source != SourceLive && o.Source != SourcePCAP {
		return fmt.Errorf("unsupported observation source %q", o.Source)
	}
	switch o.Service.Coordinates {
	case CoordinatesLogical:
		if o.Authority.Logical == nil || o.Authority.Correlation != "verified" || o.Source == SourcePCAP {
			return fmt.Errorf("logical coordinates require live verified authority")
		}
	case CoordinatesWire:
	default:
		return fmt.Errorf("unsupported coordinate space %q", o.Service.Coordinates)
	}
	count := 0
	for _, present := range []bool{o.Modbus != nil, o.DNP3 != nil, o.IEC104 != nil, o.CIP != nil} {
		if present {
			count++
		}
	}
	if count > 1 || o.Quality.Decoded && count != 1 {
		return fmt.Errorf("observation requires one matching decoded protocol record")
	}
	matches := false
	switch o.Service.Protocol {
	case "modbus":
		matches = o.Modbus != nil
	case "dnp3":
		matches = o.DNP3 != nil
	case "iec104":
		matches = o.IEC104 != nil
	case "cip":
		matches = o.CIP != nil
	default:
		return fmt.Errorf("unsupported observation protocol %q", o.Service.Protocol)
	}
	if count == 1 && !matches {
		return fmt.Errorf("protocol record does not match service protocol")
	}
	return nil
}
