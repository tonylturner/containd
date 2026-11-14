// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	dpengine "github.com/tonylturner/containd/pkg/dp/engine"
)

func TestDS34ConsumersRuleAPI(t *testing.T) {
	result := dpengine.PreviewRuleResponse{MatchCount: 2, Pairing: &dpengine.PairingPreview{
		Unpaired: 1, Unknown: 1, Reasons: []string{"autonomous_rule_required", "pairing_unknown"}}}
	eng := &previewMockEngine{result: result}
	server := newTestServerWithEngine(&mockStore{cfg: config.DefaultConfig()}, nil, eng)
	rule := config.Rule{ID: "autonomous", Action: config.ActionAllow, ICS: config.ICSPredicate{
		Protocol: "iec104", MessageClass: "autonomous", Direction: "response", TypeIDs: []int{1}, COT: []int{3}}}
	rec := requestStage(t, server, http.MethodPost, "/firewall/rules/preview", rule)
	var got dpengine.PreviewRuleResponse
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil || !reflect.DeepEqual(got, result) ||
		eng.entry.ICS.MessageClass != "autonomous" {
		t.Fatalf("preview roundtrip: %d %s entry=%+v", rec.Code, rec.Body, eng.entry)
	}
}
