// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package conntrack

import "testing"

func TestParseLine(t *testing.T) {
	line := "ipv4     2 tcp      6 431999 ESTABLISHED src=10.0.0.2 dst=10.0.0.1 sport=51514 dport=443 src=10.0.0.1 dst=10.0.0.2 sport=443 dport=51514 [ASSURED] mark=0 use=1"
	got := parseLine(line)

	if got.Proto != "tcp" {
		t.Fatalf("proto=%q, want tcp", got.Proto)
	}
	if got.TimeoutSecs != 431999 {
		t.Fatalf("timeout=%d, want 431999", got.TimeoutSecs)
	}
	if got.State != "ESTABLISHED" {
		t.Fatalf("state=%q, want ESTABLISHED", got.State)
	}
	if got.Src != "10.0.0.2" || got.Dst != "10.0.0.1" || got.Sport != "51514" || got.Dport != "443" {
		t.Fatalf("unexpected origin tuple: %+v", got)
	}
	if got.ReplySrc != "10.0.0.1" || got.ReplyDst != "10.0.0.2" || got.ReplySport != "443" || got.ReplyDport != "51514" {
		t.Fatalf("unexpected reply tuple: %+v", got)
	}
	if !got.Assured {
		t.Fatal("expected assured flag")
	}
	if got.Mark != "0" {
		t.Fatalf("mark=%q, want 0", got.Mark)
	}
}
