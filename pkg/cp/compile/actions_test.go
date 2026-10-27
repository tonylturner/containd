// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"reflect"
	"testing"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/rules"
)

// The snapshot carries each rule's action parameters, with a zero burst
// resolved to one second of packets.
func TestCompileCopiesActionParameters(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Firewall.Rules = []config.Rule{
		{ID: "police", Action: config.ActionRateLimit, RateLimit: &config.RateLimitConfig{PacketsPerSecond: 50}},
		{ID: "police-burst", Action: config.ActionRateLimit, RateLimit: &config.RateLimitConfig{PacketsPerSecond: 50, Burst: 5}},
		{ID: "label", Action: config.ActionTag, Tag: "plc"},
		{ID: "reject", Action: config.ActionReset, Protocols: []config.Protocol{{Name: "tcp", Port: "23"}}},
	}
	snap, err := CompileSnapshot(cfg)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]rules.Entry{}
	for _, e := range snap.Firewall {
		got[e.ID] = e
	}
	if rl := got["police"].RateLimit; !reflect.DeepEqual(rl, &rules.RateLimit{PacketsPerSecond: 50, Burst: 50}) {
		t.Fatalf("police rate = %+v", rl)
	}
	if rl := got["police-burst"].RateLimit; !reflect.DeepEqual(rl, &rules.RateLimit{PacketsPerSecond: 50, Burst: 5}) {
		t.Fatalf("police-burst rate = %+v", rl)
	}
	if e := got["label"]; e.Action != rules.ActionTag || e.Tag != "plc" || e.RateLimit != nil {
		t.Fatalf("label = %+v", e)
	}
	if e := got["reject"]; e.Action != rules.ActionReset || e.Tag != "" || e.RateLimit != nil {
		t.Fatalf("reject = %+v", e)
	}
	// The snapshot owns its rate: changing the config afterwards does not
	// reach it.
	cfg.Firewall.Rules[1].RateLimit.Burst = 99
	if got["police-burst"].RateLimit.Burst != 5 {
		t.Fatal("snapshot shares the config's rate limit")
	}
}
