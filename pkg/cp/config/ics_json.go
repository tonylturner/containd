// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package config

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type icsPredicateJSON struct {
	Protocol      string     `json:"protocol,omitempty"`
	FunctionCode  []int      `json:"functionCode,omitempty"`
	UnitID        *uint8     `json:"unitId,omitempty"`
	Addresses     []string   `json:"addresses,omitempty"`
	ObjectClasses []uint16   `json:"objectClasses,omitempty"`
	ReadOnly      bool       `json:"readOnly,omitempty"`
	WriteOnly     bool       `json:"writeOnly,omitempty"`
	Direction     string     `json:"direction,omitempty"`
	Mode          string     `json:"mode,omitempty"`
	TypeIDs       []int      `json:"typeIds,omitempty"`
	Classes       []string   `json:"classes,omitempty"`
	CA            []uint16   `json:"ca,omitempty"`
	IOA           []IOARange `json:"ioa,omitempty"`
}

func (p ICSPredicate) MarshalJSON() ([]byte, error) {
	out := icsPredicateJSON{
		Protocol:      p.Protocol,
		UnitID:        p.UnitID,
		Addresses:     p.Addresses,
		ObjectClasses: p.ObjectClasses,
		ReadOnly:      p.ReadOnly,
		WriteOnly:     p.WriteOnly,
		Direction:     p.Direction,
		Mode:          p.Mode,
		TypeIDs:       p.TypeIDs,
		Classes:       p.Classes,
		CA:            p.CA,
		IOA:           p.IOA,
	}
	if len(p.FunctionCode) > 0 {
		out.FunctionCode = make([]int, 0, len(p.FunctionCode))
		for _, code := range p.FunctionCode {
			out.FunctionCode = append(out.FunctionCode, int(code))
		}
	}
	return json.Marshal(out)
}

// UnmarshalJSON decodes an ICS predicate strictly (spec §6.2): unknown
// and duplicate keys are errors, the IEC104 list fields reject null, empty
// lists and null elements, and keys a protocol does not support are
// rejected by presence (so "writeOnly": false on iec104 is an error).
// Every accepted functionCode form stays accepted. A JSON null predicate
// decodes to the empty predicate.
func (p *ICSPredicate) UnmarshalJSON(data []byte) error {
	if isJSONNull(data) {
		*p = ICSPredicate{}
		return nil
	}
	fields, err := decodeStrictObject(data, icsPredicateKeys)
	if err != nil {
		return fmt.Errorf("ics: %w", err)
	}
	var out ICSPredicate
	for _, key := range icsPredicateKeys {
		raw, ok := fields[key]
		if !ok {
			continue
		}
		if err := out.decodeField(key, raw); err != nil {
			return err
		}
	}
	if err := checkICSKeysForProtocol(out.Protocol, fields); err != nil {
		return err
	}
	*p = out
	return nil
}

// icsPredicateKeys lists every ICS predicate key in its wire spelling.
// Matching is exact: encoding/json's case-insensitive field matching does
// not apply to predicates.
var icsPredicateKeys = []string{
	"protocol", "functionCode", "unitId", "addresses", "objectClasses",
	"readOnly", "writeOnly", "direction", "mode",
	"typeIds", "classes", "ca", "ioa",
}

// iec104ForbiddenKeys are the generic keys an iec104 predicate must not
// carry, even with a zero value.
var iec104ForbiddenKeys = []string{"functionCode", "unitId", "addresses", "objectClasses", "writeOnly"}

// iec104OnlyKeys are the keys only an iec104 predicate may carry.
var iec104OnlyKeys = []string{"typeIds", "classes", "ca", "ioa"}

func (p *ICSPredicate) decodeField(key string, raw json.RawMessage) error {
	var err error
	switch key {
	case "protocol":
		err = json.Unmarshal(raw, &p.Protocol)
	case "functionCode":
		if !isJSONNull(raw) {
			p.FunctionCode, err = decodeFunctionCodes(raw)
		}
	case "unitId":
		err = json.Unmarshal(raw, &p.UnitID)
	case "addresses":
		err = json.Unmarshal(raw, &p.Addresses)
	case "objectClasses":
		err = json.Unmarshal(raw, &p.ObjectClasses)
	case "readOnly":
		err = json.Unmarshal(raw, &p.ReadOnly)
	case "writeOnly":
		err = json.Unmarshal(raw, &p.WriteOnly)
	case "direction":
		err = json.Unmarshal(raw, &p.Direction)
	case "mode":
		err = json.Unmarshal(raw, &p.Mode)
	case "typeIds":
		p.TypeIDs, err = decodeIECList[int](raw)
	case "classes":
		p.Classes, err = decodeIECList[string](raw)
	case "ca":
		p.CA, err = decodeIECList[uint16](raw)
	case "ioa":
		p.IOA, err = decodeIECList[IOARange](raw)
	}
	if err != nil {
		return fmt.Errorf("ics %s: %w", key, err)
	}
	return nil
}

func checkICSKeysForProtocol(protocol string, fields map[string]json.RawMessage) error {
	switch protocol {
	case "":
		// Semantic values without a protocol are a validation error;
		// Validate checks them by value so programmatic configs are covered.
		return nil
	case ICSProtocolIEC104:
		for _, key := range iec104ForbiddenKeys {
			if _, ok := fields[key]; ok {
				return fmt.Errorf("ics %s is not supported for protocol iec104", key)
			}
		}
	default:
		for _, key := range iec104OnlyKeys {
			if _, ok := fields[key]; ok {
				return fmt.Errorf("ics %s is only supported for protocol iec104", key)
			}
		}
	}
	return nil
}

// decodeIECList decodes one of the IEC104 list fields. Absent means
// "match any", so null, [] and null elements are errors rather than
// silently widening or narrowing the rule.
func decodeIECList[T any](raw json.RawMessage) ([]T, error) {
	if isJSONNull(raw) {
		return nil, errors.New("must not be null; omit the field to match any value")
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, errors.New("must not be empty; omit the field to match any value")
	}
	out := make([]T, len(items))
	for i, item := range items {
		if isJSONNull(item) {
			return nil, fmt.Errorf("item %d must not be null", i)
		}
		if err := json.Unmarshal(item, &out[i]); err != nil {
			return nil, fmt.Errorf("item %d: %w", i, err)
		}
	}
	return out, nil
}

// UnmarshalJSON decodes an IOA range strictly: exactly "start" and "end",
// both required integers.
func (r *IOARange) UnmarshalJSON(data []byte) error {
	fields, err := decodeStrictObject(data, []string{"start", "end"})
	if err != nil {
		return err
	}
	var out IOARange
	for _, f := range []struct {
		key string
		dst *uint32
	}{{"start", &out.Start}, {"end", &out.End}} {
		raw, ok := fields[f.key]
		if !ok {
			return fmt.Errorf("range needs %q", f.key)
		}
		if isJSONNull(raw) {
			return fmt.Errorf("range %q must not be null", f.key)
		}
		if err := json.Unmarshal(raw, f.dst); err != nil {
			return fmt.Errorf("range %q: %w", f.key, err)
		}
	}
	*r = out
	return nil
}

func decodeFunctionCodes(raw json.RawMessage) ([]uint8, error) {
	var ints []int
	if err := json.Unmarshal(raw, &ints); err == nil {
		return intsToUint8(ints)
	}

	var stringsList []string
	if err := json.Unmarshal(raw, &stringsList); err == nil {
		ints = make([]int, 0, len(stringsList))
		for _, item := range stringsList {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			parsed, err := strconv.Atoi(item)
			if err != nil {
				return nil, fmt.Errorf("invalid functionCode value %q", item)
			}
			ints = append(ints, parsed)
		}
		return intsToUint8(ints)
	}

	var intMap map[string]int
	if err := json.Unmarshal(raw, &intMap); err == nil {
		return mapValuesToUint8(intMap, func(v int) (int, error) { return v, nil })
	}

	var stringMap map[string]string
	if err := json.Unmarshal(raw, &stringMap); err == nil {
		return mapValuesToUint8(stringMap, func(v string) (int, error) {
			v = strings.TrimSpace(v)
			if v == "" {
				return 0, nil
			}
			parsed, err := strconv.Atoi(v)
			if err != nil {
				return 0, fmt.Errorf("invalid functionCode value %q", v)
			}
			return parsed, nil
		})
	}

	var singleInt int
	if err := json.Unmarshal(raw, &singleInt); err == nil {
		return intsToUint8([]int{singleInt})
	}

	var singleString string
	if err := json.Unmarshal(raw, &singleString); err == nil {
		singleString = strings.TrimSpace(singleString)
		if singleString == "" {
			return nil, nil
		}
		if decoded, err := base64.StdEncoding.DecodeString(singleString); err == nil {
			return append([]uint8(nil), decoded...), nil
		}
		if parsed, err := strconv.Atoi(singleString); err == nil {
			return intsToUint8([]int{parsed})
		}
		return nil, fmt.Errorf("invalid functionCode value %q", singleString)
	}

	return nil, fmt.Errorf("invalid functionCode payload")
}

func intsToUint8(values []int) ([]uint8, error) {
	out := make([]uint8, 0, len(values))
	for _, value := range values {
		if value < 0 || value > 255 {
			return nil, fmt.Errorf("functionCode out of range: %d", value)
		}
		out = append(out, uint8(value))
	}
	return out, nil
}

func mapValuesToUint8[T any](values map[string]T, parse func(T) (int, error)) ([]uint8, error) {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		li, errI := strconv.Atoi(keys[i])
		lj, errJ := strconv.Atoi(keys[j])
		if errI == nil && errJ == nil {
			return li < lj
		}
		return keys[i] < keys[j]
	})

	ints := make([]int, 0, len(keys))
	for _, key := range keys {
		value, err := parse(values[key])
		if err != nil {
			return nil, err
		}
		if value == 0 {
			if strValue, ok := any(values[key]).(string); ok && strings.TrimSpace(strValue) == "" {
				continue
			}
		}
		ints = append(ints, value)
	}
	return intsToUint8(ints)
}
