// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"os"
	"regexp"
	"strconv"
	"testing"

	"gopkg.in/yaml.v3"
)

// The web UI and the OpenAPI description repeat MaxZoneNameBytes as a
// number; they must change with it.
func TestZoneNameLimitCopiesMatch(t *testing.T) {
	ui, err := os.ReadFile("../../../ui/lib/validate.ts")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^export const MAX_ZONE_NAME_BYTES = (\d+);$`).FindSubmatch(ui)
	if m == nil {
		t.Fatal("ui/lib/validate.ts no longer declares MAX_ZONE_NAME_BYTES as a number")
	}
	if got, _ := strconv.Atoi(string(m[1])); got != MaxZoneNameBytes {
		t.Errorf("ui/lib/validate.ts MAX_ZONE_NAME_BYTES = %d, want %d", got, MaxZoneNameBytes)
	}

	data, err := os.ReadFile("../../../docs/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]struct {
					MaxLength *int `yaml:"maxLength"`
				} `yaml:"properties"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}
	name := spec.Components.Schemas["Zone"].Properties["name"].MaxLength
	if name == nil {
		t.Fatal("docs/openapi.yaml Zone.name has no maxLength")
	}
	if *name != MaxZoneNameBytes {
		t.Errorf("docs/openapi.yaml Zone.name maxLength = %d, want %d", *name, MaxZoneNameBytes)
	}
}
