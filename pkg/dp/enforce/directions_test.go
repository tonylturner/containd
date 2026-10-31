// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"fmt"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestTransportDirectionIntersection(t *testing.T) {
	for _, target := range []chainTarget{targetForward, targetGateInput, targetGateReply} {
		for _, zoned := range []bool{false, true} {
			for _, via := range []bool{false, true} {
				for _, originalOnly := range []bool{false, true} {
					t.Run(fmt.Sprintf("target=%d/zones=%v/via=%v/original=%v", target, zoned, via, originalOnly), func(t *testing.T) {
						snap := gateSnapshot()
						e := rules.Entry{ID: "inspect", Action: rules.ActionAllow,
							Protocols: []rules.Protocol{{Name: "tcp", Port: "80"}}}
						if zoned {
							e.SourceZones, e.DestZones = []string{"wan"}, []string{"ot"}
						}
						if via {
							e.ViaForwards = []string{"pf-web"}
						}
						p, err := newPredicates(snap, 100)
						if err != nil {
							t.Fatal(err)
						}
						lines, err := p.transportLines(target, e, true, "queue num 100", originalOnly)
						if err != nil {
							t.Fatal(err)
						}
						var tracked []string
						for _, line := range lines {
							if strings.Count(line, "ct direction ") > 1 {
								t.Fatalf("direction repeated: %s", line)
							}
							if strings.HasPrefix(line, trackedState) {
								tracked = append(tracked, line)
								if originalOnly && !strings.Contains(line, "ct direction original") {
									t.Fatalf("original-only line lost restriction: %s", line)
								}
								if via && strings.Contains(line, "ct direction reply") {
									assertText(t, line, `oifname "eth0"`)
								}
							}
						}
						want := 1
						if target == targetGateReply && originalOnly {
							want = 0
						} else if target == targetForward && !originalOnly && (zoned || via) {
							want = 2
						}
						if len(tracked) != want {
							t.Fatalf("got %d tracked alternatives, want %d: %v", len(tracked), want, tracked)
						}
						if want == 2 {
							assertText(t, tracked[0], "ct direction original")
							assertText(t, tracked[1], "ct direction reply")
						} else if want == 1 && target == targetGateReply {
							assertText(t, tracked[0], "ct direction reply")
						}
					})
				}
			}
		}
	}
}

func TestMeterDirectionIntersection(t *testing.T) {
	snap := gateSnapshot()
	e := rules.Entry{ID: "meter-via", Action: rules.ActionRateLimit,
		SourceZones: []string{"wan"}, DestZones: []string{"ot"}, ViaForwards: []string{"pf-web"},
		Protocols: []rules.Protocol{{Name: "tcp", Port: "80"}}, RateLimit: &rules.RateLimit{PacketsPerSecond: 10}}
	p, err := newPredicates(snap, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []chainTarget{targetForward, targetGateInput, targetGateReply} {
		t.Run(fmt.Sprint(target), func(t *testing.T) {
			raw, err := compileMeterEntry(e, p.lowering(target), true, 0)
			if err != nil {
				t.Fatal(err)
			}
			lines, err := p.guardFor(target, e, raw)
			if err != nil {
				t.Fatal(err)
			}
			want := 1
			if target == targetForward {
				want = 2
			}
			if len(lines) != want {
				t.Fatalf("got %d meter alternatives, want %d: %v", len(lines), want, lines)
			}
			for _, line := range lines {
				if strings.Count(line, "ct direction ") != 1 {
					t.Fatalf("meter direction missing or repeated: %s", line)
				}
			}
			if target != targetGateReply {
				assertText(t, lines[0], "ct direction original", `iifname "eth0"`)
			}
			if target != targetGateInput {
				assertText(t, lines[len(lines)-1], "ct direction reply", `oifname "eth0"`)
			}
		})
	}
}
