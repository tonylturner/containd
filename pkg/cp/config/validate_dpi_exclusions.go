// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package config

import (
	"fmt"
	"net"
	"strings"
)

func validateDomainExclusions(exclusions []DPIExclusion) error {
	for _, x := range exclusions {
		if x.Type == "domain" && !validExclusionDomain(x.Value) {
			return fmt.Errorf("dataplane.dpiExclusions: invalid domain %q; use an exact DNS name or *.suffix", x.Value)
		}
	}
	return nil
}

func validExclusionDomain(value string) bool {
	name := strings.TrimSuffix(value, ".")
	name = strings.TrimPrefix(name, "*.")
	if name == "" || len(name) > 253 || net.ParseIP(name) != nil {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
