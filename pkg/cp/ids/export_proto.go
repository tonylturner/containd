// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package ids

import (
	"errors"
	"fmt"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
)

// ErrUnexportableProto marks a rule whose protocol a Suricata or Snort
// rule cannot express. Rendering it with the generic "ip" keyword would
// fire on unrelated traffic, so the rule is not exported.
var ErrUnexportableProto = errors.New("protocol cannot be exported")

// checkExportableProto rejects IEC 60870-5-104 rules: neither engine has
// an iec104 keyword, and containd does not translate IEC rules.
func checkExportableProto(rule config.IDSRule) error {
	if strings.EqualFold(strings.TrimSpace(rule.Proto), config.ICSProtocolIEC104) {
		return fmt.Errorf("rule %s: %w: %s", rule.ID, ErrUnexportableProto, rule.Proto)
	}
	return nil
}
