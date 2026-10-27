// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// MaxICSAddress is the largest address an ICS rule can name. 32 bits hold
// every address the protocols carry: DNP3 point indices are 32-bit and
// Modbus register addresses are 16-bit.
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
	if low, err = parseICSAddress(lowText); err != nil {
		return 0, 0, err
	}
	if !isRange {
		return low, low, nil
	}
	if high, err = parseICSAddress(highText); err != nil {
		return 0, 0, err
	}
	if low > high {
		return 0, 0, fmt.Errorf("range starts at %d after its end %d", low, high)
	}
	return low, high, nil
}

// parseICSAddress parses one decimal or 0x hex address value.
func parseICSAddress(text string) (uint32, error) {
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
