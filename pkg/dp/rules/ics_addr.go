// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// MaxICSAddress is the largest address an ICS rule can name. 32 bits hold
// every address the protocols carry: DNP3 point indices and OPC UA numeric
// node IDs are 32-bit, S7 byte offsets fit in 24 bits and Modbus register
// addresses in 16.
const MaxICSAddress = math.MaxUint32

// ICSAddressMax is the largest address an ICS rule for protocol can name:
// 65535 for Modbus, whose PDU carries a 16-bit address, MaxICSAddress for
// the other protocols.
func ICSAddressMax(protocol string) uint32 {
	if protocol == "modbus" {
		return math.MaxUint16
	}
	return MaxICSAddress
}

// ParseICSAddressSpec parses one entry of an ICS rule's addresses: a
// single value ("256", "0x0100") or an inclusive range low-high
// ("100-511", "0x0100-0x01FF"). Each value is decimal or hex with a 0x
// prefix, unsigned and at most MaxICSAddress; spaces around a value are
// ignored. A range needs low <= high. A single value returns it as both
// low and high.
func ParseICSAddressSpec(spec string) (low, high uint32, err error) {
	if strings.HasPrefix(strings.TrimSpace(spec), "-") {
		return 0, 0, errors.New("negative values are not addresses")
	}
	lowText, highText, isRange := strings.Cut(spec, "-")
	if low, err = ParseICSAddress(lowText); err != nil {
		return 0, 0, err
	}
	if !isRange {
		return low, low, nil
	}
	if high, err = ParseICSAddress(highText); err != nil {
		return 0, 0, err
	}
	if low > high {
		return 0, 0, fmt.Errorf("range starts at %d after its end %d", low, high)
	}
	return low, high, nil
}

// ParseICSAddress parses one decimal or 0x hex address value, spaces
// around it ignored.
func ParseICSAddress(text string) (uint32, error) {
	text = strings.TrimSpace(text)
	digits, base := text, 10
	if strings.HasPrefix(text, "0x") || strings.HasPrefix(text, "0X") {
		digits, base = text[2:], 16
	}
	if digits == "" {
		return 0, fmt.Errorf("%q is not a decimal or 0x hex value", text)
	}
	v, err := strconv.ParseUint(digits, base, 32)
	if errors.Is(err, strconv.ErrRange) {
		return 0, fmt.Errorf("%s exceeds the largest address %d", text, uint32(MaxICSAddress))
	}
	if err != nil {
		return 0, fmt.Errorf("%q is not a decimal or 0x hex value", text)
	}
	return uint32(v), nil
}

// AddressSpan is an inclusive range of ICS addresses.
type AddressSpan struct {
	Low, High uint32
}

// addrSet is an ICS address predicate's parsed specifications, merged into
// sorted, disjoint, non-adjacent ranges so that a span covered by several
// entries together lies inside one range. listed records that the
// predicate names any. An entry ParseICSAddressSpec refuses, which
// validation rejects, leaves ranges empty: the predicate then holds no
// address rather than only its parseable entries.
type addrSet struct {
	listed bool
	ranges []AddressSpan
}

func compileAddrs(specs []string) addrSet {
	set := addrSet{listed: len(specs) > 0}
	for _, spec := range specs {
		low, high, err := ParseICSAddressSpec(spec)
		if err != nil {
			return addrSet{listed: true}
		}
		set.ranges = append(set.ranges, AddressSpan{Low: low, High: high})
	}
	sort.Slice(set.ranges, func(i, j int) bool { return set.ranges[i].Low < set.ranges[j].Low })
	merged := set.ranges[:0]
	for _, r := range set.ranges {
		if n := len(merged); n > 0 && uint64(r.Low) <= uint64(merged[n-1].High)+1 {
			merged[n-1].High = max(merged[n-1].High, r.High)
			continue
		}
		merged = append(merged, r)
	}
	set.ranges = merged
	return set
}

// holdsAll reports whether spans is non-empty and every span lies inside
// one of the set's ranges.
func (s addrSet) holdsAll(spans []AddressSpan) bool {
	if len(spans) == 0 {
		return false
	}
	for _, sp := range spans {
		if !s.holds(sp) {
			return false
		}
	}
	return true
}

func (s addrSet) holds(sp AddressSpan) bool {
	for _, r := range s.ranges {
		if sp.Low >= r.Low && sp.High <= r.High {
			return true
		}
	}
	return false
}

// meetsAny reports whether any span shares an address with the set.
func (s addrSet) meetsAny(spans []AddressSpan) bool {
	for _, sp := range spans {
		for _, r := range s.ranges {
			if sp.Low <= r.High && r.Low <= sp.High {
				return true
			}
		}
	}
	return false
}
