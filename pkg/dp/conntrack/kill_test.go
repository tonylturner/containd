// SPDX-License-Identifier: Apache-2.0
package conntrack

import (
	"context"
	"errors"
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
