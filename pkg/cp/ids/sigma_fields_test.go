// SPDX-License-Identifier: Apache-2.0
package ids

import "testing"

func TestSNMPSigmaFieldsMatchEmittedMetadata(t *testing.T) {
	if got := normalizeField("community"); got != "attr.community" {
		t.Fatalf("community=%q, want attr.community", got)
	}
	if got := normalizeField("community_auth"); got != "" {
		t.Fatalf("obsolete community_auth=%q, want unsupported", got)
	}
	if got := normalizeField("first_oid"); got != "" {
		t.Fatalf("obsolete first_oid=%q, want unsupported", got)
	}
	if got := normalizeField("oids"); got != "" {
		t.Fatalf("array-valued OIDs=%q, want unsupported scalar field", got)
	}
}

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
