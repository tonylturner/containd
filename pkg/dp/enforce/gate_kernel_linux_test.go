// SPDX-License-Identifier: Apache-2.0
//go:build linux

package enforce

import (
	"fmt"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// gateKernelSnapshot is the policy the gate kernel tests install: a
// default-deny firewall that admits the client to the LAN and WAN web
// ports and port-forwards WAN connections to the server, source NAT
// towards the WAN, a local management service, and a selection of every
// web port towards the LAN and WAN zones that excludes port 8082 from the
// client and treats the second LAN host as an ICS asset.
func gateKernelSnapshot() *rules.Snapshot {
	port := func(p int) []rules.Protocol { return []rules.Protocol{{Name: "tcp", Port: fmt.Sprint(p)}} }
	return &rules.Snapshot{
		Default:          rules.ActionDeny,
		ZoneIfaces:       map[string][]string{"client": {"gs0"}, "lan": {"gsbr"}, "wan": {"gs2"}},
		IdentityBindings: []rules.IdentityBinding{{IP: gateClientV4, Identities: []string{"ops"}}},
		LocalInput:       []rules.LocalServiceRule{{ID: "mgmt", Zone: "client", Proto: "tcp", Port: 8080}},
		Firewall: []rules.Entry{
			{ID: "client-web", SourceZones: []string{"client"}, DestZones: []string{"lan"}, Protocols: port(80), Action: rules.ActionAllow},
			{ID: "client-8082", SourceZones: []string{"client"}, DestZones: []string{"lan"}, Protocols: port(8082), Action: rules.ActionAllow},
			{ID: "client-wan", SourceZones: []string{"client"}, DestZones: []string{"wan"}, Protocols: port(80), Action: rules.ActionAllow},
			{ID: "ops-8081", Identities: []string{"ops"}, SourceZones: []string{"client"}, DestZones: []string{"lan"}, Protocols: port(8081), Action: rules.ActionAllow},
		},
		NAT: rules.NATConfig{Enabled: true, EgressZone: "wan", SourceZones: []string{"client"},
			PortForwards: []rules.PortForward{{ID: "web", Enabled: true, IngressZone: "wan", Proto: "tcp", ListenPort: gateForwardPort, DestIP: gateServerV4, DestPort: 80}}},
		Gate: rules.GateSelection{
			Enabled:    true,
			Zones:      []rules.GateZone{{Name: "lan", Index: 1, Devices: []string{"gsbr"}}, {Name: "wan", Index: 2, Devices: []string{"gs2"}}},
			Include:    []rules.GateEntry{{DestZones: []string{"lan", "wan"}, Ports: []rules.GatePortRange{{Lo: 80, Hi: 80}, {Lo: 8080, Hi: 8082}}}},
			Exclude:    []rules.GateEntry{{SourceDevices: []string{"gs0"}, Ports: []rules.GatePortRange{{Lo: 8082, Hi: 8082}}}},
			ICSCIDRs:   []string{gateHairpinV4 + "/32"},
			FailPolicy: "closed", DownloadMode: "hold",
		},
	}
}

// gateKernelCompiler compiles for the default listener ports in state.
func gateKernelCompiler(state GateAdmitState) *Compiler {
	c := NewCompiler()
	c.GatePlainPort, c.GateMasqPort = DefaultGatePlainPort, DefaultGateMasqPort
	c.GateAdmit = state
	return c
}

// TestGateKernel installs compiled rulesets in this namespace and drives
// connections through them: selected connections reach the proxy on the
// listener their selection chose and their servers see the client (or the
// masquerade today's NAT gives them); excluded, local and pre-existing
// connections are untouched; a selected connection without a listener, or
// refused, is reset, never forwarded; the policy decides gated connections
// in both directions as it decides forwarded ones.
func TestGateKernel(t *testing.T) {
	lab := newGateLab(t)
	proxy := startGateProxy(t, lab)
	for _, port := range []int{80, 8080, 8081, 8082} {
		lab.serve(t, lab.server, gateServerV4, port)
	}
	lab.serve(t, lab.server, gateServerV6, 80)
	lab.serve(t, lab.hairpin, gateHairpinV4, 80)
	lab.serve(t, lab.wan, gateWANHostV4, 80)
	lab.serveLocal(t, "0.0.0.0", 8080)
	lab.nftIn(t, lab.server, "add table inet probe\nadd counter inet probe syn\nadd chain inet probe in { type filter hook input priority filter; }\nadd rule inet probe in tcp flags & (syn | ack) == syn counter name \"syn\"\n")
	serverSYNs := func() uint64 { return lab.counter(t, lab.server, "probe", "syn") }
	open := func() { lab.install(t, gateKernelCompiler(GateAdmitOpen), gateKernelSnapshot()) }
	viaGate := func(peer, msg string) string { return "peer=" + peer + " msg=via-gate " + msg }
	plain := func(peer, msg string) string { return "peer=" + peer + " msg=" + msg }

	t.Run("selected_ipv4_reaches_plain_listener", func(t *testing.T) {
		open()
		port, reply := lab.exchange(t, lab.client, gateServerV4, 80, "t1")
		if want := viaGate(gateClientV4, "t1"); reply != want {
			t.Fatalf("reply %q, want %q", reply, want)
		}
		a := proxy.accepted(t, gateClientV4+":"+port)
		if a.local != gateServerV4+":80" || a.original != a.local || a.masq {
			t.Fatalf("accepted %+v, want plain listener, local and original %s:80", a, gateServerV4)
		}
	})
	t.Run("selected_ipv6_reaches_plain_listener", func(t *testing.T) {
		open()
		port, reply := lab.exchange(t, lab.client, gateServerV6, 80, "t1v6")
		if want := viaGate(gateClientV6, "t1v6"); reply != want {
			t.Fatalf("reply %q, want %q", reply, want)
		}
		a := proxy.accepted(t, "["+gateClientV6+"]:"+port)
		if a.local != "["+gateServerV6+"]:80" || a.original != a.local || a.masq {
			t.Fatalf("accepted %+v", a)
		}
	})
	t.Run("zone_masquerade_selects_masq_listener", func(t *testing.T) {
		open()
		port, reply := lab.exchange(t, lab.client, gateWANHostV4, 80, "t2")
		if want := viaGate(gateWANRouter, "t2"); reply != want {
			t.Fatalf("reply %q, want %q (upstream masqueraded by its socket mark)", reply, want)
		}
		if a := proxy.accepted(t, gateClientV4+":"+port); !a.masq || a.local != gateWANHostV4+":80" {
			t.Fatalf("accepted %+v, want the masquerading listener", a)
		}
	})
	t.Run("port_forward_grant_and_return_path_masquerade", func(t *testing.T) {
		open()
		port, reply := lab.exchange(t, lab.wan, gateWANRouter, gateForwardPort, "t3")
		if want := viaGate(gateLANRouter, "t3"); reply != want {
			t.Fatalf("reply %q, want %q", reply, want)
		}
		a := proxy.accepted(t, gateWANHostV4+":"+port)
		if !a.masq || a.local != gateServerV4+":80" || a.original != fmt.Sprintf("%s:%d", gateWANRouter, gateForwardPort) {
			t.Fatalf("accepted %+v, want masquerading listener, local %s:80, original %s:%d", a, gateServerV4, gateWANRouter, gateForwardPort)
		}
	})
	t.Run("excluded_and_local_untouched", func(t *testing.T) {
		open()
		n := proxy.count()
		port, reply := lab.exchange(t, lab.client, gateServerV4, 8082, "t4")
		if want := plain(gateClientV4, "t4"); reply != want {
			t.Fatalf("excluded connection: reply %q, want %q", reply, want)
		}
		if proxy.find(gateClientV4+":"+port) != nil {
			t.Fatal("excluded connection reached the gate")
		}
		port, reply = lab.exchange(t, lab.client, gateClientRouter, 8080, "t4l")
		if want := plain(gateClientV4, "local t4l"); reply != want {
			t.Fatalf("local service: reply %q, want %q", reply, want)
		}
		if proxy.count() != n || proxy.find(gateClientV4+":"+port) != nil {
			t.Fatal("a local service connection reached the gate")
		}
	})
	t.Run("forward_denied_is_denied_in_gate_in", func(t *testing.T) {
		open()
		n, syns := proxy.count(), serverSYNs()
		if c := lab.connect(t, lab.client, gateServerV4, 8080); c.err != "error None" {
			t.Fatalf("connect to a port no rule admits: %q, want a timeout", c.err)
		}
		if proxy.count() != n || serverSYNs() != syns {
			t.Fatal("a denied SYN reached the gate or the server")
		}
	})
	t.Run("listener_absent_resets_without_forwarding", func(t *testing.T) {
		c := gateKernelCompiler(GateAdmitOpen)
		c.GatePlainPort, c.GateMasqPort = DefaultGatePlainPort+2, DefaultGateMasqPort+2
		lab.install(t, c, gateKernelSnapshot())
		n, syns := proxy.count(), serverSYNs()
		if c := lab.connect(t, lab.client, gateServerV4, 80); c.err != "error 111" {
			t.Fatalf("connect: %q, want ECONNREFUSED", c.err)
		}
		if serverSYNs() != syns {
			t.Fatal("SYN leaked to the server")
		}
		if proxy.count() != n {
			t.Fatal("the proxy accepted a connection for another port")
		}
	})
	t.Run("refuse_resets_and_passes_ics_endpoints", func(t *testing.T) {
		lab.install(t, gateKernelCompiler(GateAdmitRefuse), gateKernelSnapshot())
		n, syns := proxy.count(), serverSYNs()
		if c := lab.connect(t, lab.client, gateServerV4, 80); c.err != "error 111" {
			t.Fatalf("connect while refusing: %q, want ECONNREFUSED", c.err)
		}
		if serverSYNs() != syns || proxy.count() != n {
			t.Fatal("a refused SYN reached the server or the gate")
		}
		if _, reply := lab.exchange(t, lab.client, gateHairpinV4, 80, "t6"); reply != plain(gateClientV4, "t6") {
			t.Fatalf("ICS endpoint while refusing: %q, want a plain connection", reply)
		}
		if proxy.count() != n {
			t.Fatal("the ICS endpoint's connection reached the gate")
		}
	})
	t.Run("pass_forwards_ungated", func(t *testing.T) {
		lab.install(t, gateKernelCompiler(GateAdmitPass), gateKernelSnapshot())
		n := proxy.count()
		if _, reply := lab.exchange(t, lab.client, gateServerV4, 80, "t7"); reply != plain(gateClientV4, "t7") {
			t.Fatalf("connection while passing: %q, want a plain connection", reply)
		}
		if proxy.count() != n {
			t.Fatal("a passed connection reached the gate")
		}
	})
	t.Run("switch_script_changes_admission", func(t *testing.T) {
		c := gateKernelCompiler(GateAdmitRefuse)
		lab.install(t, c, gateKernelSnapshot())
		if c := lab.connect(t, lab.client, gateServerV4, 80); c.err != "error 111" {
			t.Fatalf("connect while refusing: %q", c.err)
		}
		lab.nftIn(t, "", c.GateAdmitSwitch(GateAdmitOpen))
		if _, reply := lab.exchange(t, lab.client, gateServerV4, 80, "t8"); reply != viaGate(gateClientV4, "t8") {
			t.Fatalf("after switching open: %q", reply)
		}
		lab.nftIn(t, "", c.GateAdmitSwitch(GateAdmitPass))
		if _, reply := lab.exchange(t, lab.client, gateServerV4, 80, "t8p"); reply != plain(gateClientV4, "t8p") {
			t.Fatalf("after switching to pass: %q", reply)
		}
	})
	t.Run("existing_connection_stays_plain_across_selection", func(t *testing.T) {
		snap := gateKernelSnapshot()
		snap.Gate = rules.GateSelection{}
		lab.install(t, gateKernelCompiler(GateAdmitOpen), snap)
		c := lab.connect(t, lab.client, gateServerV4, 80)
		open()
		if reply := c.exchange(t, "t9"); reply != plain(gateClientV4, "t9") {
			t.Fatalf("pre-existing connection changed: %q", reply)
		}
		if proxy.find(gateClientV4+":"+c.port) != nil {
			t.Fatal("pre-existing connection diverted")
		}
		if _, reply := lab.exchange(t, lab.client, gateServerV4, 80, "t9n"); reply != viaGate(gateClientV4, "t9n") {
			t.Fatalf("new connection after the selection: %q", reply)
		}
	})
	t.Run("untracked_pickup_stays_plain", func(t *testing.T) {
		// Without any ruleset the connection is unknown to connection
		// tracking, which picks its next packet up as "new"; only a SYN is
		// selected.
		lab.uninstall(t)
		c := lab.connect(t, lab.client, gateServerV4, 80)
		open()
		if reply := c.exchange(t, "t10"); reply != plain(gateClientV4, "t10") {
			t.Fatalf("picked-up connection changed: %q", reply)
		}
		if proxy.find(gateClientV4+":"+c.port) != nil {
			t.Fatal("picked-up connection diverted")
		}
	})
	t.Run("reply_direction_follows_the_recheck", func(t *testing.T) {
		// The proxy answers by itself once released. With the identity
		// still bound the answer reaches the client; after a reapply that
		// unbinds it, the output-side recheck drops the gate's reply.
		for _, bound := range []bool{true, false} {
			t.Run(fmt.Sprintf("bound=%v", bound), func(t *testing.T) {
				open()
				release := proxy.holding()
				defer release()
				c := lab.connect(t, lab.client, gateServerV4, 8081)
				if c.err != "" {
					t.Fatalf("connect: %s", c.err)
				}
				proxy.accepted(t, gateClientV4+":"+c.port)
				if !bound {
					snap := gateKernelSnapshot()
					snap.IdentityBindings = nil
					lab.install(t, gateKernelCompiler(GateAdmitOpen), snap)
				}
				release()
				reply := c.exchange(t, "t11")
				if bound && reply != "hello" {
					t.Fatalf("reply while bound: %q, want hello", reply)
				}
				if !bound && reply != "error None" {
					t.Fatalf("reply after unbinding: %q, want a timeout", reply)
				}
			})
		}
	})
	t.Run("temporary_block_scoped_to_gated_connections", func(t *testing.T) {
		open()
		lab.nftIn(t, "", "add element inet containd block_hosts { "+gateClientV4+" timeout 30s }\n")
		defer lab.nftIn(t, "", "flush set inet containd block_hosts\n")
		n := proxy.count()
		if c := lab.connect(t, lab.client, gateServerV4, 80); c.err != "error None" {
			t.Fatalf("blocked client's gated connect: %q, want a timeout", c.err)
		}
		if proxy.count() != n {
			t.Fatal("a blocked client's connection reached the gate")
		}
		if _, reply := lab.exchange(t, lab.client, gateClientRouter, 8080, "t12"); reply != plain(gateClientV4, "local t12") {
			t.Fatalf("blocked client's management connection: %q", reply)
		}
	})
}
