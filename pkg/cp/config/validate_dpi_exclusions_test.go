// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package config

import (
	"strings"
	"testing"
)

func TestValidateDomainExclusions(t *testing.T) {
	for _, value := range []string{"example.com", "EXAMPLE.com.", "*.example.com", "*.example.com.", "localhost", "xn--bcher-kva.example"} {
		t.Run(value, func(t *testing.T) {
			if err := validateDataPlane(DataPlaneConfig{DPIExclusions: []DPIExclusion{{Type: "domain", Value: value}}}); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, value := range []string{"", "*", ".", "*.", "*example.com", "foo.*.com", "example..com", "https://example.com", "example.com:443", " example.com", "example.com ", "-bad.example", "bad-.example", "_bad.example", "bücher.example", "1.2.3.4", "*.1.2.3.4", "example.com..", strings.Repeat("a", 64) + ".com", strings.Repeat("a.", 128) + "com"} {
		t.Run(value, func(t *testing.T) {
			if err := validateDataPlane(DataPlaneConfig{DPIExclusions: []DPIExclusion{{Type: "domain", Value: value}}}); err == nil {
				t.Fatal("accepted invalid domain")
			}
		})
	}
}
