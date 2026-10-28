// SPDX-License-Identifier: Apache-2.0
package ids

import "testing"

func TestCIPScalarSigmaFields(t *testing.T) {
	for _, key := range []string{"msp", "enip_status", "connection_id", "connected_sequence",
		"response_reserved", "additional_status_count", "multi_service_decoded_count", "msp_index",
		"connection_point", "io_context_known", "io_data_hex"} {
		if got := normalizeField(key); got != "attr."+key {
			t.Fatalf("%s=%s", key, got)
		}
	}
	for _, key := range []string{"additional_status", "msp_index_path"} {
		if normalizeField(key) != "" {
			t.Fatalf("array %s has no Sigma scalar evaluator", key)
		}
	}
	r, err := ConvertSigmaYAML([]byte("title: MSP child\nid: cip-msp\nlogsource:\n  product: containd\ndetection:\n  selection:\n    msp: true\n  condition: selection\n"))
	if err != nil || r.When.Field != "attr.msp" || r.When.Value != true {
		t.Fatalf("boolean MSP selection: %+v %v", r, err)
	}
}
