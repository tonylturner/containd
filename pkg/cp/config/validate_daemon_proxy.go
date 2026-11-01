// SPDX-License-Identifier: Apache-2.0
package config

import (
	"errors"
	"strings"
)

// ValidateProxySiteID accepts 1..64 ASCII letters, digits, underscores or
// hyphens, starting with a letter or underscore (an nginx upstream identifier).
func ValidateProxySiteID(s string) error {
	if len(s) == 0 || len(s) > 64 || !(s[0] == '_' || s[0] >= 'a' && s[0] <= 'z' || s[0] >= 'A' && s[0] <= 'Z') {
		return errors.New("site name must be a 1..64 byte ASCII identifier starting with a letter or underscore")
	}
	for i := range len(s) {
		if !asciiAlnum(s[i]) && s[i] != '_' && s[i] != '-' {
			return errors.New("site name contains an invalid identifier character")
		}
	}
	return nil
}

// ValidateProxyHostname accepts a host or a leading whole-label DNS wildcard
// such as *.example.com. Bare *, suffix wildcards, regexes and nginx's special
// dot-prefix shorthand are deliberately unsupported.
func ValidateProxyHostname(s string) error {
	if strings.HasPrefix(s, "*.") {
		s = s[2:]
		if !strings.Contains(s, ".") || strings.ContainsAny(s, ":") {
			return errors.New("wildcard must prefix a DNS suffix")
		}
		// Numeric IP suffixes are not DNS wildcard names.
		allNumeric := true
		for i := range len(s) {
			if (s[i] < '0' || s[i] > '9') && s[i] != '.' {
				allNumeric = false
			}
		}
		if allNumeric {
			return errors.New("wildcard must prefix a DNS suffix")
		}
	}
	return ValidateDaemonHost(s)
}

// ValidateProxyCertRef accepts an opaque 1..128 byte ASCII file stem.
// Dots, separators and traversal are forbidden; certificate file checks belong
// to runtime preflight.
func ValidateProxyCertRef(s string) error {
	if len(s) == 0 || len(s) > 128 || !asciiAlnum(s[0]) {
		return errors.New("certRef must be a non-empty ASCII certificate identifier")
	}
	for i := range len(s) {
		if !asciiAlnum(s[i]) && s[i] != '_' && s[i] != '-' {
			return errors.New("certRef must contain only letters, digits, underscores or hyphens")
		}
	}
	return nil
}

// ValidateProxyListenZone checks a zone name interpolated into a daemon-file
// comment. Membership in the configured zones is a separate contextual check.
func ValidateProxyListenZone(s string) error {
	if s == "" {
		return errors.New("listen zone cannot be empty")
	}
	for i := range len(s) {
		if !asciiAlnum(s[i]) && !strings.ContainsRune("_.-", rune(s[i])) {
			return errors.New("listen zone must contain only ASCII letters, digits, dots, underscores or hyphens")
		}
	}
	return nil
}
