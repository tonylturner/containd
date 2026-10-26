// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"fmt"
	"slices"
	"strings"
)

// maxIfnameLen is the longest Linux interface name in bytes: IFNAMSIZ less
// its terminating NUL.
const maxIfnameLen = 15

// ValidateInterfaceName checks a kernel interface name that containd writes
// into nftables. It must be a name Linux accepts for a device: 1 to 15
// bytes, without '/', ':' or whitespace, and neither "." nor "..". nft must
// also match it exactly, so it may not hold '"', which ends an nft string,
// '*', which nft reads as a wildcard, '\', which escapes one, or control
// characters.
func ValidateInterfaceName(name string) error {
	if name == "" || len(name) > maxIfnameLen {
		return fmt.Errorf("invalid interface name %q: want 1-%d bytes", name, maxIfnameLen)
	}
	if name == "." || name == ".." {
		return fmt.Errorf("invalid interface name %q", name)
	}
	for i := 0; i < len(name); i++ {
		switch b := name[i]; {
		case b < 0x20 || b == 0x7f:
			return fmt.Errorf("invalid interface name %q: control character", name)
		// 0xa0 is whitespace to the kernel's isspace.
		case b == ' ' || b == 0xa0:
			return fmt.Errorf("invalid interface name %q: whitespace", name)
		case strings.IndexByte(`/:"*\`, b) >= 0:
			return fmt.Errorf("invalid interface name %q: %q is not allowed", name, b)
		}
	}
	return nil
}

// ifnameLiteral is name as an nft string, refused unless it passes
// ValidateInterfaceName.
func ifnameLiteral(name string) (string, error) {
	if err := ValidateInterfaceName(name); err != nil {
		return "", err
	}
	return `"` + name + `"`, nil
}

// ifnameSet is names as an nft anonymous set of strings, sorted.
func ifnameSet(names []string) (string, error) {
	lits := make([]string, 0, len(names))
	for _, n := range names {
		lit, err := ifnameLiteral(n)
		if err != nil {
			return "", err
		}
		lits = append(lits, lit)
	}
	return "{ " + strings.Join(sortedUnique(lits), ", ") + " }", nil
}

// sortedUnique returns the distinct values of list, sorted.
func sortedUnique(list []string) []string {
	out := slices.Clone(list)
	slices.Sort(out)
	return slices.Compact(out)
}
