// SPDX-License-Identifier: Apache-2.0
package rules

// InspectionUnavailable names a static cause that prevents semantic inspection.
// An absent decoder key is enabled, matching the decoder registry.
func InspectionUnavailable(enabled bool, protocols map[string]bool, protocol string) string {
	if !enabled {
		return "master"
	}
	if on, set := protocols[protocol]; set && !on {
		return "decoder"
	}
	return ""
}
