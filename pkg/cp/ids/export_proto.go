// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package ids

import (
	"errors"
	"fmt"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/ics"
)

// ErrUnexportableProto marks a rule whose protocol a Suricata or Snort
// rule cannot express. Rendering it with the generic "ip" keyword would
// fire on unrelated traffic, so the rule is not exported.
var ErrUnexportableProto = errors.New("protocol cannot be exported")

// checkExportableProto refuses obsolete native labels and IEC 60870-5-104:
// neither exporter can safely express them as a generic IP rule.
func checkExportableProto(rule config.IDSRule) error {
	if ics.Removed(rule.Proto) || strings.EqualFold(strings.TrimSpace(rule.Proto), config.ICSProtocolIEC104) {
		return fmt.Errorf("rule %s: %w: %s", rule.ID, ErrUnexportableProto, rule.Proto)
	}
	return nil
}
