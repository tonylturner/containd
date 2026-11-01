// SPDX-License-Identifier: Apache-2.0

//go:build linux

package capture

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/flow"
)

// TestKernelNFLogOrientsRuleHitsByConntrack logs both directions of a
// loopback UDP exchange and checks that each rule hit carries the
// packet's key with conntrack's direction: the request as sent, the reply
// marked DirReverse. The ct state matches enable conntrack in the
// namespace, as containd's ruleset does.
func TestKernelNFLogOrientsRuleHitsByConntrack(t *testing.T) {
	requireKernel(t)
	const group = 77
	nft(t, `table inet containd_nflog_test {
  chain output {
    type filter hook output priority 0;
    udp dport 39999 ct state new log prefix "containd:probe-request:DENY " group 77
    udp sport 39999 ct state established log prefix "containd:probe-reply:RATE_LIMIT " group 77
  }
}
`)
	t.Cleanup(func() { nft(t, "delete table inet containd_nflog_test\n") })

	sink := &recordingSink{}
	stop, err := StartNFLog(context.Background(), group, sink, nil, nil)
	if err != nil {
		t.Fatalf("StartNFLog with conntrack direction: %v", err)
	}
	defer stop()

	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 39999})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	if err := server.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, peer, err := server.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.WriteToUDP([]byte("pong"), peer); err != nil {
		t.Fatal(err)
	}

	clientPort := uint16(client.LocalAddr().(*net.UDPAddr).Port)
	loopback := net.IPv4(127, 0, 0, 1)
	want := map[string]flow.Key{
		"probe-request": {SrcIP: loopback, DstIP: loopback, SrcPort: clientPort, DstPort: 39999, Proto: 17, Dir: flow.DirForward},
		"probe-reply":   {SrcIP: loopback, DstIP: loopback, SrcPort: 39999, DstPort: clientPort, Proto: 17, Dir: flow.DirReverse},
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		got := map[string]*flow.Key{}
		for _, hit := range sink.recorded() {
			got[hit.ev.Attributes["ruleId"].(string)] = hit.key
		}
		if len(got) == len(want) {
			for rule, key := range want {
				if got[rule] == nil || got[rule].Hash() != key.Hash() {
					t.Fatalf("%s: key %+v, want %+v", rule, got[rule], key)
				}
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("rule hits = %v, want one per direction", got)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
