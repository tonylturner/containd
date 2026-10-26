// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// Identity binding bounds. Every label of a binding is an nftables address
// set in the policy table, so the counts stay small.
const (
	MaxIdentityBindings    = 4096
	MaxBindingIdentities   = 16
	MaxIdentityLabelLength = 64
)

// validateIdentityBindings checks firewall.identityBindings: each binding
// tags one unicast IPv4 or IPv6 address, at most once, with 1 to
// MaxBindingIdentities distinct labels.
func validateIdentityBindings(bindings []IdentityBinding) error {
	if len(bindings) > MaxIdentityBindings {
		return fmt.Errorf("firewall.identityBindings has %d bindings; at most %d are allowed", len(bindings), MaxIdentityBindings)
	}
	seen := make(map[string]struct{}, len(bindings))
	for i, b := range bindings {
		addr, ok := rules.BindingAddr(b.IP)
		if !ok || addr.IsUnspecified() || addr.IsMulticast() {
			return fmt.Errorf("firewall.identityBindings[%d]: ip %q must be a unicast IPv4 or IPv6 address without a zone", i, b.IP)
		}
		key := addr.String()
		if _, dup := seen[key]; dup {
			return fmt.Errorf("firewall.identityBindings[%d]: ip %s is already bound", i, key)
		}
		seen[key] = struct{}{}
		if err := validateBindingIdentities(b.Identities); err != nil {
			return fmt.Errorf("firewall.identityBindings[%d] (%s): %w", i, key, err)
		}
	}
	return nil
}

func validateBindingIdentities(ids []string) error {
	if len(ids) == 0 || len(ids) > MaxBindingIdentities {
		return fmt.Errorf("needs 1 to %d identities, got %d", MaxBindingIdentities, len(ids))
	}
	labels := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if err := ValidateIdentityLabel(id); err != nil {
			return err
		}
		if _, dup := labels[id]; dup {
			return fmt.Errorf("identity %q is listed twice", id)
		}
		labels[id] = struct{}{}
	}
	return nil
}

// ValidateIdentityLabel checks one binding label: 1 to
// MaxIdentityLabelLength bytes of printable characters without surrounding
// spaces. Labels match rule identities exactly and case-sensitively.
func ValidateIdentityLabel(id string) error {
	if id == "" || len(id) > MaxIdentityLabelLength {
		return fmt.Errorf("identity %q must be 1 to %d bytes", id, MaxIdentityLabelLength)
	}
	if !utf8.ValidString(id) {
		return fmt.Errorf("identity %q is not valid UTF-8", id)
	}
	if strings.TrimSpace(id) != id {
		return fmt.Errorf("identity %q has surrounding spaces", id)
	}
	for _, r := range id {
		if !unicode.IsPrint(r) {
			return fmt.Errorf("identity %q has a non-printable character", id)
		}
	}
	return nil
}
