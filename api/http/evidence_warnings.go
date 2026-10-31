// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"encoding/json"
	"strings"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/learn"
)

// Warnings are deliberately outside immutable content and certification. Sharing
// a protocol is a conservative overlap heuristic, not policy-impact evaluation.
func addLegacyOverlapWarnings(data json.RawMessage, running []config.Rule, page bool) (json.RawMessage, error) {
	enrich := func(s *learn.Suggestion) {
		s.LegacyOverlaps = []learn.LegacyOverlap{}
		for _, old := range running {
			if !strings.HasPrefix(old.ID, "learned-") {
				continue
			}
			for _, rule := range s.Content.Rules {
				if old.ICS.Protocol == "" || strings.EqualFold(old.ICS.Protocol, rule.ICS.Protocol) {
					s.LegacyOverlaps = append(s.LegacyOverlaps, learn.LegacyOverlap{RuleID: old.ID, Reason: "Legacy rule shares protocol scope; review precedence and service/address overlap. It will not be removed."})
					break
				}
			}
		}
	}
	if page {
		var result learn.SuggestionPage
		if err := json.Unmarshal(data, &result); err != nil {
			return nil, err
		}
		for i := range result.Items {
			enrich(&result.Items[i])
		}
		return json.Marshal(result)
	}
	var result learn.Suggestion
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	enrich(&result)
	return json.Marshal(result)
}
