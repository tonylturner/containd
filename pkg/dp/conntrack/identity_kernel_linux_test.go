// SPDX-License-Identifier: Apache-2.0

//go:build linux

package conntrack_test

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/conntrack"
	"github.com/tonylturner/containd/pkg/dp/enforce"
)

// Uses the same disposable routed namespace harness as operator kill tests.
// Two clients share a source port, forcing masquerade to disambiguate replies.
func TestKernelTransportIdentityMasquerade(t *testing.T) {
	if os.Getenv("CONTAIND_NETNS_KERNEL_TEST") != "1" {
		t.Skip("opt-in isolated kernel test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	lab := newRoutedLab(t, ctx, false, func(l *routedLab) string {
		return fmt.Sprintf("add rule inet containd test_snat iifname ctclient ip daddr %s tcp dport 25000 masquerade to :50000-50002\n", l.server)
	})
	startPeer(t, ctx, lab.serverNS, "server", net.JoinHostPort(lab.server, "25000"))
	client := startPeer(t, ctx, lab.clientNS, "client", lab.client)
	zones, err := enforce.NewNftApplier().ZoneSetters(ctx)
	if err != nil || len(zones) != 0 {
		t.Fatalf("zone authority: %+v, %v", zones, err)
	}
	reader := conntrack.NewIdentityReader()
	defer reader.Close()
	var entries []conntrack.Evidence
	for i, address := range []string{lab.client, lab.otherClient} {
		name := fmt.Sprint(i)
		if got := client.command(t, "dial "+name+" "+net.JoinHostPort(lab.server, "25000")+" 41001 "+address); got != "ok" {
			t.Fatal(got)
		}
		if got := client.command(t, "echo "+name); got != "ok" {
			t.Fatal(got)
		}
		original := conntrack.Tuple{Family: 2, Protocol: 6,
			Source:      netip.AddrPortFrom(netip.MustParseAddr(address), 41001),
			Destination: netip.AddrPortFrom(netip.MustParseAddr(lab.server), 25000)}
		e, err := reader.Lookup(ctx, original)
		if err != nil {
			t.Fatal(err)
		}
		reverse, err := reader.Lookup(ctx, e.Reply)
		if err != nil || reverse.ID != e.ID || reverse.Start != e.Start ||
			reverse.Original != original || reverse.Reply != e.Reply {
			t.Fatalf("reply selector = %+v, %v; original=%+v", reverse, err, e)
		}
		if e.Reply.Destination.Addr().String() != lab.routerServer || e.Reply.Destination.Port() == 41001 {
			t.Fatalf("missing SNAT remap: %+v", e)
		}
		entries = append(entries, e)
	}
	if entries[0].ID == entries[1].ID || entries[0].Reply.Destination.Port() == entries[1].Reply.Destination.Port() {
		t.Fatalf("colliding clients shared kernel identity: %+v", entries)
	}
}

func TestKernelTransportIdentityDNATAndHairpin(t *testing.T) {
	if os.Getenv("CONTAIND_NETNS_KERNEL_TEST") != "1" {
		t.Skip("opt-in isolated kernel test")
	}
	for _, hairpin := range []bool{false, true} {
		name := "dnat"
		if hairpin {
			name = "hairpin"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			lab := newRoutedLab(t, ctx, false, func(l *routedLab) string {
				backend := l.server
				if hairpin {
					backend = l.otherClient
				}
				return fmt.Sprintf("add rule inet containd test_dnat ip daddr %s tcp dport 1502 dnat ip to %s:25000\n", l.vip, backend) +
					fmt.Sprintf("add rule inet containd test_snat iifname ctclient ip daddr %s tcp dport 25000 masquerade to :50000-50002\n", backend)
			})
			backend, serverNS, masq := lab.server, lab.serverNS, lab.routerServer
			if hairpin {
				backend, serverNS, masq = lab.otherClient, lab.clientNS, lab.routerClient
			}
			startPeer(t, ctx, serverNS, "server", net.JoinHostPort(backend, "25000"))
			client := startPeer(t, ctx, lab.clientNS, "client", lab.client)
			if got := client.command(t, "dial selected "+net.JoinHostPort(lab.vip, "1502")+" 41001"); got != "ok" {
				t.Fatal(got)
			}
			if got := client.command(t, "echo selected"); got != "ok" {
				t.Fatal(got)
			}
			reader := conntrack.NewIdentityReader()
			defer reader.Close()
			original := conntrack.Tuple{Family: 2, Protocol: 6,
				Source:      netip.AddrPortFrom(netip.MustParseAddr(lab.client), 41001),
				Destination: netip.AddrPortFrom(netip.MustParseAddr(lab.vip), 1502)}
			e, err := reader.Lookup(ctx, original)
			if err != nil {
				t.Fatal(err)
			}
			reply, err := reader.Lookup(ctx, e.Reply)
			if err != nil || reply.Original != original || reply.ID != e.ID || reply.Start != e.Start ||
				reply.Reply != e.Reply || e.Reply.Source.Addr().String() != backend || e.Reply.Source.Port() != 25000 ||
				e.Reply.Destination.Addr().String() != masq {
				t.Fatalf("DNAT membership: %+v, %+v, %v", e, reply, err)
			}
		})
	}
}
