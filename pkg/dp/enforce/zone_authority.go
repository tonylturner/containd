// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"context"
	"encoding/json"
	"fmt"
)

// ZoneSetter identifies a rule that can assign a conntrack zone. It does not
// describe containd's interface policy zones, which are unrelated to CT zones.
type ZoneSetter struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Chain  string `json:"chain"`
	Handle uint64 `json:"handle"`
}

// ZoneSetters inspects every nft table in this network namespace, including
// tables owned by other applications. An error is not evidence of zone zero.
func (a *NftApplier) ZoneSetters(ctx context.Context) ([]ZoneSetter, error) {
	doc, err := a.list(ctx, "list", "ruleset")
	if err != nil {
		return nil, err
	}
	return parseZoneSetters(doc)
}

func parseZoneSetters(doc []byte) ([]ZoneSetter, error) {
	// nftItems alone accepts a missing/null nftables member. Such a document
	// cannot establish that the namespace has no zone setters.
	var root struct {
		Items json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(doc, &root); err != nil {
		return nil, fmt.Errorf("decode nft ruleset: %w", err)
	}
	if len(root.Items) == 0 || string(root.Items) == "null" {
		return nil, fmt.Errorf("nft ruleset has no item array")
	}
	items, err := nftItems(doc)
	if err != nil {
		return nil, err
	}
	setters := []ZoneSetter{}
	for _, item := range items {
		if len(item) != 1 {
			return nil, fmt.Errorf("invalid nft ruleset item")
		}
		raw, ok := item["rule"]
		if !ok {
			continue
		}
		var rule struct {
			ZoneSetter
			Expr []map[string]json.RawMessage `json:"expr"`
		}
		if err := json.Unmarshal(raw, &rule); err != nil {
			return nil, fmt.Errorf("decode nft zone rule: %w", err)
		}
		if rule.Family == "" || rule.Table == "" || rule.Chain == "" || rule.Expr == nil {
			return nil, fmt.Errorf("incomplete nft rule")
		}
		found := false
		for _, expr := range rule.Expr {
			if len(expr) != 1 {
				return nil, fmt.Errorf("invalid nft rule expression")
			}
			if raw, ok := expr["mangle"]; ok {
				var m *struct {
					Key struct {
						CT *struct {
							Key string `json:"key"`
						} `json:"ct"`
					} `json:"key"`
				}
				if err := json.Unmarshal(raw, &m); err != nil {
					return nil, fmt.Errorf("decode nft mangle: %w", err)
				}
				if m == nil || m.Key.CT != nil && m.Key.CT.Key == "" {
					return nil, fmt.Errorf("invalid nft mangle expression")
				}
				found = found || m.Key.CT != nil && m.Key.CT.Key == "zone"
			}
			if raw, ok := expr["xt"]; ok {
				var xt *struct {
					Name string `json:"name"`
				}
				if err := json.Unmarshal(raw, &xt); err != nil {
					return nil, fmt.Errorf("decode nft xt target: %w", err)
				}
				if xt == nil || xt.Name == "" {
					return nil, fmt.Errorf("invalid nft xt target")
				}
				found = found || xt.Name == "CT"
			}
		}
		if found {
			setters = append(setters, rule.ZoneSetter)
		}
	}
	return setters, nil
}
