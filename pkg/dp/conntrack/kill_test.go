// SPDX-License-Identifier: Apache-2.0
package conntrack

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"
)

func TestKillSteps(t *testing.T) {
	entries := []Entry{{Proto: "tcp", Src: "192.0.2.1", Dst: "198.51.100.1", Sport: "1234", Dport: "443", ReplySrc: "10.0.0.1", ReplyDst: "203.0.113.1", ReplySport: "8443", ReplyDport: "5678"}, {Proto: "tcp", Src: "192.0.2.1", Dst: "198.51.100.1", Sport: "1235", Dport: "443"}, {Proto: "udp", Src: "192.0.2.1", Dst: "198.51.100.1", Sport: "1234", Dport: "443"}}
	for _, tc := range []struct {
		name, scope         string
		blockErr, deleteErr bool
		want                int
	}{{"exact", "connection", false, false, 1}, {"service", "client-service", false, false, 2}, {"block failure", "connection", true, false, 0}, {"delete failure", "connection", false, true, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			blocked := false
			deleted := 0
			req := KillRequest{DeleteRequest: DeleteRequest{Proto: "tcp", Src: "192.0.2.1", Dst: "198.51.100.1", Sport: 1234, Dport: 443}, Scope: tc.scope}
			result, err := kill(context.Background(), req, func(_ context.Context, e []Entry, scope string, ttl time.Duration) error {
				if e[0] != entries[0] || scope != tc.scope || ttl != time.Minute {
					t.Fatalf("revocation %+v %s %s", e, scope, ttl)
				}
				if tc.blockErr {
					return errors.New("denied")
				}
				blocked = true
				return nil
			}, func(context.Context, int) ([]Entry, error) { return entries, nil }, func(_ context.Context, r DeleteRequest) error {
				if !blocked {
					t.Fatal("deleted before revoking")
				}
				if r.Src != entries[0].Src || r.Dst != entries[0].Dst {
					t.Fatal("not original NAT tuple")
				}
				if tc.deleteErr {
					return errors.New("delete denied")
				}
				deleted++
				return nil
			})
			if err != nil || deleted != tc.want || result.Deleted != tc.want || result.RevocationInstalled == tc.blockErr || result.ConntrackDeleted == (tc.blockErr || tc.deleteErr) {
				t.Fatalf("result %+v err %v", result, err)
			}
			if result.RevocationInstalled && (result.BlockedUntil == nil || result.Closure == "not signalled") {
				t.Fatalf("missing steps: %+v", result)
			}
		})
	}
}
func TestKillUnavailableAndEmpty(t *testing.T) {
	req := KillRequest{DeleteRequest: DeleteRequest{Proto: "udp", Src: "2001:db8::1", Dst: "2001:db8::2", Sport: 1000, Dport: 502}}
	for _, err := range []error{errors.New("permission denied"), nil} {
		_, got := kill(context.Background(), req, func(context.Context, []Entry, string, time.Duration) error { t.Fatal("must not revoke"); return nil }, func(context.Context, int) ([]Entry, error) { return []Entry{}, err }, nil)
		if got == nil {
			t.Fatal("expected reason")
		}
	}
}
func TestKillValidation(t *testing.T) {
	base := KillRequest{DeleteRequest: DeleteRequest{Proto: "tcp", Src: "192.0.2.1", Dst: "192.0.2.2", Sport: 1234, Dport: 443}}
	cases := []KillRequest{base, base, base, base, base}
	cases[0].Scope = "host"
	cases[1].DurationSecs = 3601
	cases[2].Sport = 0
	cases[3].Dst = "2001:db8::1"
	cases[4].Proto = "icmp"
	for _, r := range cases {
		if r.Validate() == nil {
			t.Fatalf("accepted %+v", r)
		}
	}
	if err := base.Validate(); err != nil || base.Scope != "connection" || base.DurationSecs != 60 {
		t.Fatalf("defaults %+v %v", base, err)
	}
}

func TestKillValidationICMP(t *testing.T) {
	v4 := KillRequest{DeleteRequest: DeleteRequest{Proto: "ICMP", Src: "192.0.2.1", Dst: "192.0.2.2", ICMPID: 0, ICMPType: 8}}
	v6 := KillRequest{DeleteRequest: DeleteRequest{Proto: "icmpv6", Src: "2001:db8::1", Dst: "2001:db8::2", ICMPID: 65535, ICMPType: 139, ICMPCode: 2}}
	for _, ok := range []KillRequest{v4, v6} {
		if err := ok.Validate(); err != nil {
			t.Fatalf("rejected %+v: %v", ok, err)
		}
	}
	bad := []func(*KillRequest){
		func(r *KillRequest) { r.Proto = "icmpv6" },                          // IPv4 endpoints
		func(r *KillRequest) { r.Src, r.Dst = "2001:db8::1", "2001:db8::2" }, // ICMP over IPv6
		func(r *KillRequest) { r.ICMPType = 0 },                              // echo reply never opens an entry
		func(r *KillRequest) { r.ICMPType = 3 },                              // errors are not connections
		func(r *KillRequest) { r.ICMPType = 128 },                            // an ICMPv6 type
		func(r *KillRequest) { r.ICMPID = 65536 },
		func(r *KillRequest) { r.ICMPID = -1 },
		func(r *KillRequest) { r.ICMPCode = 256 },
		func(r *KillRequest) { r.Sport = 1 },
		func(r *KillRequest) { r.Dport = 1 },
	}
	for i, change := range bad {
		r := v4
		change(&r)
		if r.Validate() == nil {
			t.Fatalf("case %d accepted %+v", i, r)
		}
	}
	tcp := KillRequest{DeleteRequest: DeleteRequest{Proto: "tcp", Src: "192.0.2.1", Dst: "192.0.2.2", Sport: 1234, Dport: 443, ICMPType: 8}}
	if tcp.Validate() == nil {
		t.Fatal("accepted ICMP fields on a TCP tuple")
	}
}

func TestKillICMPSelection(t *testing.T) {
	ping := func(src, dst, id, typ string) Entry {
		return Entry{Proto: "icmp", Src: src, Dst: dst, ICMPID: id, ICMPType: typ, ICMPCode: "0", ReplySrc: dst, ReplyDst: src, ReplyICMPID: id, ReplyICMPType: "0", ReplyICMPCode: "0"}
	}
	selected := ping("192.0.2.1", "198.51.100.1", "4660", "8")
	sibling := ping("192.0.2.1", "198.51.100.1", "4661", "8")
	entries := []Entry{
		selected, sibling,
		ping("192.0.2.1", "198.51.100.1", "4660", "13"), // another query type
		ping("192.0.2.9", "198.51.100.1", "4660", "8"),  // another client
		ping("192.0.2.1", "198.51.100.2", "4660", "8"),  // another destination
		{Proto: "udp", Src: "192.0.2.1", Dst: "198.51.100.1", Sport: "4660", Dport: "8"},
	}
	for scope, want := range map[string][]Entry{"connection": {selected}, "client-service": {selected, sibling}} {
		var revoked []Entry
		var deleted []DeleteRequest
		req := KillRequest{DeleteRequest: DeleteRequest{Proto: "icmp", Src: "192.0.2.1", Dst: "198.51.100.1", ICMPID: 4660, ICMPType: 8}, Scope: scope}
		result, err := kill(context.Background(), req, func(_ context.Context, e []Entry, _ string, _ time.Duration) error {
			revoked = e
			return nil
		}, func(context.Context, int) ([]Entry, error) { return entries, nil }, func(_ context.Context, r DeleteRequest) error {
			deleted = append(deleted, r)
			return nil
		})
		if err != nil || !result.ConntrackDeleted || result.Matched != len(want) || result.Closure != "matching packets dropped" {
			t.Fatalf("%s: %+v %v", scope, result, err)
		}
		for i, e := range want {
			id, _ := strconv.Atoi(e.ICMPID)
			if revoked[i] != e || deleted[i] != (DeleteRequest{Proto: "icmp", Src: e.Src, Dst: e.Dst, ICMPID: id, ICMPType: 8}) {
				t.Fatalf("%s: revoked %+v deleted %+v", scope, revoked, deleted)
			}
		}
	}
	req := KillRequest{DeleteRequest: DeleteRequest{Proto: "icmp", Src: "192.0.2.1", Dst: "198.51.100.1", ICMPID: 4662, ICMPType: 8}, Scope: "client-service"}
	if _, err := kill(context.Background(), req, nil, func(context.Context, int) ([]Entry, error) { return entries, nil }, nil); err == nil {
		t.Fatal("killed a service whose selected identifier is absent")
	}
}

func TestEntryOriginal(t *testing.T) {
	got, err := Entry{Proto: "icmpv6", Src: "2001:db8::1", Dst: "2001:db8::2", Sport: "9", ICMPID: "0", ICMPType: "128", ICMPCode: "0"}.Original()
	if err != nil || got != (DeleteRequest{Proto: "icmpv6", Src: "2001:db8::1", Dst: "2001:db8::2", ICMPType: 128}) {
		t.Fatalf("icmpv6 original %+v %v", got, err)
	}
	for _, e := range []Entry{{Proto: "icmp", ICMPType: "8", ICMPCode: "0"}, {Proto: "icmp", ICMPID: "-1", ICMPType: "8", ICMPCode: "0"}, {Proto: "tcp", Sport: "1", Dport: "65536"}, {Proto: "udp", Sport: "+1", Dport: "2"}} {
		if _, err := e.Original(); err == nil {
			t.Fatalf("accepted %+v", e)
		}
	}
}
