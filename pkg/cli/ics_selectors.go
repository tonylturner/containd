// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// applyICSSelector parses the protocol-specific selectors. Semantic validation
// remains authoritative on the server, including cross-field constraints.
func applyICSSelector(p *config.ICSPredicate, flag, value string) error {
	switch flag {
	case "--negative", "--test":
		if value != "true" && value != "false" {
			return fmt.Errorf("%s requires true or false", flag)
		}
		v := value == "true"
		if flag == "--negative" {
			p.Negative = &v
		} else {
			p.Test = &v
		}
		return nil
	case "--select-execute":
		if value != "select" && value != "execute" {
			return fmt.Errorf("%s requires select or execute", flag)
		}
		p.SelectExecute = value
		return nil
	case "--tags":
		p.Tags = strings.Split(value, ",")
		for i := range p.Tags {
			p.Tags[i] = strings.TrimSpace(p.Tags[i])
			if p.Tags[i] == "" {
				return fmt.Errorf("%s requires nonempty tag paths", flag)
			}
		}
		return nil
	}
	maxValue := uint64(65535)
	switch flag {
	case "--masters", "--outstations":
		maxValue = 65519
	case "--groups", "--variations", "--originators":
		maxValue = 255
	case "--command-states":
		maxValue = 2
	case "--command-qualifiers":
		maxValue = 31
	case "--cot":
		maxValue = 63
	}
	values, err := parseICSSelectorNumbers(value, flag, maxValue)
	if err != nil {
		return err
	}
	ints := make([]int, len(values))
	for i, v := range values {
		ints[i] = int(v)
	}
	switch flag {
	case "--masters":
		p.Masters = values
	case "--outstations":
		p.Outstations = values
	case "--groups":
		p.Groups = ints
	case "--variations":
		p.Variations = ints
	case "--instances":
		p.Instances = values
	case "--attributes":
		p.Attributes = values
	case "--cot":
		for _, v := range values {
			if v == 0 {
				return fmt.Errorf("--cot values must be in 1..63")
			}
		}
		p.COT = ints
	case "--command-states":
		p.CommandStates = ints
	case "--command-qualifiers":
		p.CommandQualifiers = ints
	case "--originators":
		p.Originators = ints
	default:
		return fmt.Errorf("unknown selector: %s", flag)
	}
	return nil
}

func parseICSSelectorNumbers(value, flag string, maxValue uint64) ([]uint16, error) {
	values := make([]uint16, 0)
	for _, token := range strings.Split(value, ",") {
		token = strings.TrimSpace(token)
		base := 10
		if strings.HasPrefix(strings.ToLower(token), "0x") {
			base, token = 16, token[2:]
		}
		v, err := strconv.ParseUint(token, base, 16)
		if err != nil || v > maxValue {
			return nil, fmt.Errorf("%s requires integers in 0..%d", flag, maxValue)
		}
		values = append(values, uint16(v))
	}
	return values, nil
}

func selectorCSV[T ~int | ~uint16](values []T) string {
	items := make([]string, len(values))
	for i, v := range values {
		items[i] = strconv.Itoa(int(v))
	}
	return joinCSV(items)
}

func optionalBool(value *bool) string {
	if value == nil {
		return "—"
	}
	return strconv.FormatBool(*value)
}
