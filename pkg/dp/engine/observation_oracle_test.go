// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/tonylturner/containd/pkg/common/metrics"
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/dp/session"
	"github.com/tonylturner/containd/pkg/dp/verdict"
)

type oracleSpy struct {
	cache                                                []string
	submissions, followups, deletes, updates, tombstones int
	injector                                             session.Fake
	verdicts                                             [4]float64
}

func (s *oracleSpy) BlockHostTemp(context.Context, net.IP, time.Duration) error {
	s.updates++
	return nil
}
func (s *oracleSpy) BlockFlowTemp(context.Context, net.IP, net.IP, string, string, time.Duration) error {
	s.updates++
	return nil
}

type oracleState struct {
	Cache                                                     map[string]verdict.Verdict
	Generic                                                   map[flow.MapKey]time.Time
	IEC                                                       map[string]sessionState
	CacheWrites                                               []string
	Submissions, Followups, Deletes, Updates, TombstoneWrites int
	Resets                                                    []session.Reset
	Verdicts                                                  [4]float64
	Pending                                                   int
}

func oracleSnapshot(e *Engine, s *oracleSpy) oracleState {
	out := oracleState{Cache: map[string]verdict.Verdict{}, Generic: map[flow.MapKey]time.Time{}, IEC: map[string]sessionState{},
		CacheWrites: append([]string(nil), s.cache...), Verdicts: s.verdicts, Submissions: s.submissions, Followups: s.followups, Deletes: s.deletes, Updates: s.updates, TombstoneWrites: s.tombstones, Resets: s.injector.Resets(), Pending: len(e.hooks.after.pending) + len(e.hooks.blocks.jobs)}
	for k, v := range e.verdictCache.entries {
		out.Cache[k] = v.verdict
	}
	for k, v := range e.deniedTCP {
		out.Generic[k] = v.expires
	}
	for k, v := range e.sessions.sessions {
		out.IEC[fmt.Sprint(k)] = v.state
	}
	return out
}

type oracleFlow struct {
	FirstSeen, LastSeen time.Time
	Packets, Bytes      uint64
	Closed              bool
}

func oracleFlows(e *Engine) map[flow.MapKey]oracleFlow {
	out := make(map[flow.MapKey]oracleFlow)
	for key, st := range e.flows {
		out[key] = oracleFlow{st.FirstSeen, st.LastSeen, st.Packets, st.Bytes, st.Connection.Load().Closed().Load()}
	}
	return out
}

// The oracle compares each packet, not endpoints or final cache state. Concrete
// cache-write and submission spies catch transient work, including queued jobs
// that would otherwise be invisible until a later worker tick.
func TestObservationVerdictOracle(t *testing.T) {
	cases := []struct {
		name                  string
		port                  uint16
		iec, selected, strict bool
		mode                  string
		deny                  bool
		binding               string
		keepOpen              bool
	}{
		{"standard-deny-default", 502, false, true, false, "enforce", true, "legacy", false},
		{"standard-deny-strict", 502, false, true, true, "enforce", true, "legacy", false},
		{"standard-unselected", 502, false, false, false, "", false, "observation", false},
		{"standard-mismatch", 20000, false, true, false, "enforce", true, "observation", false},
		{"2404-no-rule", 2404, true, false, false, "", false, "observation", false},
		{"2404-learn", 2404, true, true, false, "monitor", false, "legacy", false},
		{"2404-enforce", 2404, true, true, false, "enforce", false, "legacy", false},
		{"2404-learn-reuse-open", 2404, true, true, false, "monitor", false, "legacy", true},
		{"2404-enforce-reuse-open", 2404, true, true, false, "enforce", false, "legacy", true},
		{"alternate-modbus", 1502, false, true, true, "enforce", true, "observation", false},
		{"alternate-iec104", 12404, true, true, true, "enforce", true, "observation", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Unix(1800000000, 0)
			var engines [2]*Engine
			var spies [2]*oracleSpy
			proto, port := "modbus", "502"
			if tc.iec {
				proto, port = "iec104", "2404"
			}
			if tc.port == 20000 {
				proto, port = "dnp3", "20000"
			}
			snap := rules.Snapshot{Default: rules.ActionAllow}
			if tc.selected {
				action := rules.ActionAllow
				if tc.deny {
					action = rules.ActionDeny
				}
				snap.Firewall = []rules.Entry{{ID: "oracle-rule", Log: true, Protocols: []rules.Protocol{{Name: "tcp", Port: port}}, ICS: rules.ICSPredicate{Protocol: proto, Mode: tc.mode}, Action: action}}
			}
			for i := range engines {
				spy := &oracleSpy{}
				spies[i] = spy
				e, err := New(Config{Capture: capture.Config{Interfaces: []string{"eth0"}}, DPIEnabled: true, DPIMode: "enforce", ResetInjector: &spy.injector})
				if err != nil {
					t.Fatal(err)
				}
				if i == 0 {
					e.observation = nil
				} else {
					e.observation.now = func() time.Time { return now }
				}
				e.deniedTCPNow = func() time.Time { return now }
				e.sessions.now = func() time.Time { return now }
				e.verdictCache.now = func() time.Time { return now }
				e.verdictCache.changed = func(op, key string, v verdict.Verdict) {
					spy.cache = append(spy.cache, fmt.Sprintf("%s/%s/%+v", op, key, v))
				}
				e.hooks.blocks.submitted = func() { spy.submissions++ }
				e.hooks.after.submitted = func() { spy.followups++ }
				markAbort := e.sessions.markAbort
				e.sessions.markAbort = func(id string) { spy.tombstones++; markAbort(id) }
				e.sessions.ctDelete = func(context.Context, conntrack.DeleteRequest) error { spy.deletes++; return nil }
				e.updater = spy
				e.LoadRules(snap)
				if tc.strict {
					e.SetICSParsing(map[string]string{proto: "strict"})
				}
				engines[i] = e
			}
			defer func() { engines[1].observation.observer.Drain(); engines[1].observation.syncMetrics() }()
			trace := observationTrace(tc.port, tc.iec)
			// Include a duplicate payload, a continuation and FIN/RST, so the proof
			// covers both replay and bound decoding after the terminal arrival.
			trace = append(trace, trace[len(trace)-1])
			continuation := trace[2]
			continuation.TCP.Seq += uint32(len(continuation.Payload))
			trace = append(trace, continuation)
			reset := trace[0]
			reset.TCP.Flags = capture.TCPFlagRST | capture.TCPFlagACK
			reset.Payload = nil
			if !tc.keepOpen {
				trace = append(trace, reset)
			}
			drops := 0
			runPacket := func(e *Engine, pkt capture.Packet) capture.Decision {
				if tc.port != 502 || !tc.deny {
					return e.HandlePacket(pkt)
				}
				// A real enforce oracle needs inline steering authority, not
				// an AF_PACKET observation mislabeled as an enforcing verdict.
				markHandshake(&pkt)
				reply := pkt.SrcPort == tc.port
				if reply {
					pkt.Queue = policyQueue(pkt.DstIP, pkt.SrcIP, pkt.DstPort, pkt.SrcPort, true)
				} else {
					pkt.Queue = policyQueue(pkt.SrcIP, pkt.DstIP, pkt.SrcPort, pkt.DstPort, false)
				}
				return sendInline(e, pkt)
			}
			for n, pkt := range trace {
				now = now.Add(time.Millisecond)
				pkt.Timestamp = now
				var decisions [2]capture.Decision
				for i, e := range engines {
					spies[i].measureVerdicts(func() { decisions[i] = runPacket(e, pkt) })
				}
				if decisions[1].Action == capture.Drop {
					drops++
				}
				if !reflect.DeepEqual(decisions[0], decisions[1]) {
					t.Fatalf("packet %d decisions: %+v != %+v", n, decisions[0], decisions[1])
				}
				before, after := oracleSnapshot(engines[0], spies[0]), oracleSnapshot(engines[1], spies[1])
				if !reflect.DeepEqual(before, after) {
					t.Fatalf("packet %d side effects:\n%+v\n%+v", n, before, after)
				}
				if tc.port == 2404 && tc.selected && !reflect.DeepEqual(oracleFlows(engines[0]), oracleFlows(engines[1])) {
					t.Fatalf("packet %d changed table-owned flow lifecycle", n)
				}
				// Deterministically drain every scheduled job after recording submissions.
				for i, e := range engines {
					spies[i].measureVerdicts(func() {
						for len(e.hooks.blocks.jobs) > 0 {
							(<-e.hooks.blocks.jobs)()
						}
					})
				}
				if !reflect.DeepEqual(oracleSnapshot(engines[0], spies[0]), oracleSnapshot(engines[1], spies[1])) {
					t.Fatalf("packet %d differed after drain", n)
				}
			}
			if tc.port == 502 && tc.deny && drops == 0 {
				t.Fatal("deny oracle did not exercise a denied packet")
			}
			ids := 0
			for _, ev := range engines[1].Events().List(0) {
				if ev.Proto == eventfields.ProtoIdentify {
					ids++
					if ev.Attributes[eventfields.KeyBinding] != tc.binding || ev.Attributes[eventfields.KeyIdentificationState] != "confirmed" {
						t.Fatalf("identification: %+v", ev)
					}
				}
			}
			if ids != 1 {
				t.Fatalf("identifications=%d; events=%+v", ids, engines[1].Events().List(0))
			}
			for _, spy := range spies {
				if tc.binding == "observation" && (spy.submissions != 0 || spy.followups != 0 || spy.deletes != 0 || spy.updates != 0 || len(spy.injector.Resets()) != 0) {
					t.Fatalf("passive path submitted enforcement: %+v", spy)
				}
			}
			// Reuse the tuples with a fresh ISN too. In particular, 2404's
			// identity retirement must not change its independent table owner.
			reopened := observationTrace(tc.port, tc.iec)
			var retained [2]*flow.State
			var previous [2]*trackedSession
			for i, e := range engines {
				retained[i] = e.tupleStateLocked(packetKey(reopened[0]).Tuple())
				client, _ := addrPort(reopened[0].SrcIP, reopened[0].SrcPort)
				server, _ := addrPort(reopened[0].DstIP, reopened[0].DstPort)
				previous[i], _ = e.sessions.lookupLocked(client, server)
			}
			for n, pkt := range reopened {
				if n%2 == 0 {
					pkt.TCP.Seq += 1000
					if pkt.TCP.Flags&capture.TCPFlagACK != 0 {
						pkt.TCP.Ack += 2000
					}
				} else {
					pkt.TCP.Seq += 2000
					pkt.TCP.Ack += 1000
				}
				now = now.Add(time.Millisecond)
				pkt.Timestamp = now
				var a, b capture.Decision
				spies[0].measureVerdicts(func() { a = runPacket(engines[0], pkt) })
				spies[1].measureVerdicts(func() { b = runPacket(engines[1], pkt) })
				if !reflect.DeepEqual(a, b) || !reflect.DeepEqual(oracleSnapshot(engines[0], spies[0]), oracleSnapshot(engines[1], spies[1])) {
					t.Fatalf("reopen packet %d changed legacy outputs", n)
				}
				if tc.port == 2404 && tc.selected {
					for i, e := range engines {
						if st := e.tupleStateLocked(packetKey(reopened[0]).Tuple()); st != retained[i] {
							t.Fatalf("reopen packet %d replaced table-owned flow (observer=%v)", n, i == 1)
						}
					}
					if !reflect.DeepEqual(oracleFlows(engines[0]), oracleFlows(engines[1])) {
						t.Fatalf("reopen packet %d changed table-owned flow lifecycle", n)
					}
				}
				for i, e := range engines {
					spies[i].measureVerdicts(func() {
						for len(e.hooks.blocks.jobs) > 0 {
							(<-e.hooks.blocks.jobs)()
						}
					})
				}
				if !reflect.DeepEqual(oracleSnapshot(engines[0], spies[0]), oracleSnapshot(engines[1], spies[1])) {
					t.Fatalf("reopen packet %d changed drained work", n)
				}
			}
			ids = 0
			for _, ev := range engines[1].Events().List(0) {
				if ev.Proto == eventfields.ProtoIdentify {
					ids++
				}
			}
			wantIDs := 2
			if tc.port == 502 && tc.deny {
				// Inline queue metadata here has no new kernel generation
				// evidence. Do not invent a second discovery identity from
				// a SYN: the validated gate handshake owns stream replacement.
				wantIDs = 1
				for i, e := range engines {
					client, _ := addrPort(reopened[0].SrcIP, reopened[0].SrcPort)
					server, _ := addrPort(reopened[0].DstIP, reopened[0].DstPort)
					current, _ := e.sessions.lookupLocked(client, server)
					if previous[i] == nil || current == nil || current.id == previous[i].id {
						t.Fatalf("validated reconnect did not replace gate incarnation: %v -> %v", previous[i], current)
					}
					if got := ruleHits(e, "oracle-rule"); got != 2 {
						t.Fatalf("both incarnations must inspect and deny their request, hits=%d events=%+v", got, e.Events().List(0))
					}
				}
			}
			if ids != wantIDs {
				t.Fatalf("discovery identities=%d want %d", ids, wantIDs)
			}
			t.Logf("%d packets + drains identical; submissions=%d resets=%d deletes=%d followups=%d updater=%d; one %s identity per incarnation", len(trace)+len(reopened), spies[1].submissions, len(spies[1].injector.Resets()), spies[1].deletes, spies[1].followups, spies[1].updates, tc.binding)
		})
	}
}

// Live Prometheus counters are process-wide. Charge only the deltas produced by
// each engine's scheduled unit of work, so comparing two engines is meaningful.
func (s *oracleSpy) measureVerdicts(work func()) {
	actions := []string{string(verdict.AllowContinue), string(verdict.DenyDrop), string(verdict.BlockHostTemp), string(verdict.BlockFlowTemp)}
	var before [4]float64
	for i, action := range actions {
		before[i] = testutil.ToFloat64(metrics.VerdictsTotal.WithLabelValues(action))
	}
	work()
	for i, action := range actions {
		s.verdicts[i] += testutil.ToFloat64(metrics.VerdictsTotal.WithLabelValues(action)) - before[i]
	}
}
