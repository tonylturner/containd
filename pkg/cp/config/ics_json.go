// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type icsPredicateJSON struct {
	Protocol      string   `json:"protocol,omitempty"`
	FunctionCode  []int    `json:"functionCode,omitempty"`
	UnitID        *uint8   `json:"unitId,omitempty"`
	Addresses     []string `json:"addresses,omitempty"`
	ObjectClasses []uint16 `json:"objectClasses,omitempty"`
	ReadOnly      bool     `json:"readOnly,omitempty"`
	WriteOnly     bool     `json:"writeOnly,omitempty"`
	Direction     string   `json:"direction,omitempty"`
	Mode          string   `json:"mode,omitempty"`
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
	}
	if len(p.FunctionCode) > 0 {
		out.FunctionCode = make([]int, 0, len(p.FunctionCode))
		for _, code := range p.FunctionCode {
			out.FunctionCode = append(out.FunctionCode, int(code))
		}
	}
	return json.Marshal(out)
}

func (p *ICSPredicate) UnmarshalJSON(data []byte) error {
	var raw struct {
		Protocol      string          `json:"protocol,omitempty"`
		FunctionCode  json.RawMessage `json:"functionCode,omitempty"`
		UnitID        *uint8          `json:"unitId,omitempty"`
		Addresses     []string        `json:"addresses,omitempty"`
		ObjectClasses []uint16        `json:"objectClasses,omitempty"`
		ReadOnly      bool            `json:"readOnly,omitempty"`
		WriteOnly     bool            `json:"writeOnly,omitempty"`
		Direction     string          `json:"direction,omitempty"`
		Mode          string          `json:"mode,omitempty"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	*p = ICSPredicate{
		Protocol:      raw.Protocol,
		UnitID:        raw.UnitID,
		Addresses:     raw.Addresses,
		ObjectClasses: raw.ObjectClasses,
		ReadOnly:      raw.ReadOnly,
		WriteOnly:     raw.WriteOnly,
		Direction:     raw.Direction,
		Mode:          raw.Mode,
	}

	if len(raw.FunctionCode) == 0 || string(raw.FunctionCode) == "null" {
		return nil
	}

	codes, err := decodeFunctionCodes(raw.FunctionCode)
	if err != nil {
		return err
	}
	p.FunctionCode = codes
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
