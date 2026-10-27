// SPDX-License-Identifier: Apache-2.0
//go:build linux

package enforce

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TestGateSteeringKernel proves the kernel recipe that steers forwarded
// HTTP connections into a transparent (TPROXY) listener in this namespace
// and dials the server with the client's address, with raw nft and ip
// commands rather than the compiler. It builds a client namespace, a
// bridged LAN with a server and a hairpin client, and a WAN namespace
// around this namespace, which stands in for containd. It runs only when
// CONTAIND_NETNS_KERNEL_TEST=1 inside a disposable Linux container with
// NET_ADMIN, NET_RAW and SYS_ADMIN, nft, iproute2 and Python;
// scripts/gate-spike/run.sh runs it in the golang image.
//
// The kernel shipped by Docker Desktop builds nftables without the socket
// expression (CONFIG_NFT_SOCKET unset), so the recipe does not use
// `socket transparent`: the upstream dialer's SO_MARK marks the upstream
// connection in OUTPUT and the reply direction of that connection is routed
// to the local table by ct mark instead.
func TestGateSteeringKernel(t *testing.T) {
	lab := newSpikeLab(t)
	gate := startSpikeGate(t, lab)
	lab.serve(t, lab.server, spikeServerV4, 80)
	lab.serve(t, lab.server, spikeServerV6, 80)
	lab.serveLocal(t, "0.0.0.0", 8080)
	lab.nftIn(t, lab.server, "add table inet probe\nadd counter inet probe syn\nadd chain inet probe in { type filter hook input priority filter; }\nadd rule inet probe in tcp dport 80 tcp flags & (syn | ack) == syn counter name \"syn\"\n")

	t.Run("1_tproxy_accept_tuple", func(t *testing.T) {
		lab.install(t, spikeVariant{ready: true})
		before := lab.counter(t, "", "gate_spike", "fwd_syn")
		port, reply := lab.exchange(t, lab.client, spikeServerV4, 80, "t1")
		want := "peer=" + spikeClientV4 + " msg=via-gate t1"
		if reply != want {
			t.Fatalf("reply %q, want %q", reply, want)
		}
		a := gate.accepted(t, spikeClientV4+":"+port)
		if a.local != spikeServerV4+":80" || a.original != a.local {
			t.Fatalf("accepted %+v, want local and original %s:80", a, spikeServerV4)
		}
		if got := lab.counter(t, "", "gate_spike", "fwd_syn"); got != before {
			t.Fatalf("gated SYN traversed FORWARD: %d -> %d", before, got)
		}
	})
	t.Run("2_transparent_upstream_ipv4", func(t *testing.T) {
		lab.install(t, spikeVariant{ready: true})
		_, reply := lab.exchange(t, lab.client, spikeServerV4, 80, "t2")
		if want := "peer=" + spikeClientV4 + " msg=via-gate t2"; reply != want {
			t.Fatalf("reply %q, want %q", reply, want)
		}
	})
	t.Run("2_transparent_upstream_ipv6", func(t *testing.T) {
		lab.install(t, spikeVariant{ready: true})
		port, reply := lab.exchange(t, lab.client, spikeServerV6, 80, "t2v6")
		if want := "peer=" + spikeClientV6 + " msg=via-gate t2v6"; reply != want {
			t.Fatalf("reply %q, want %q", reply, want)
		}
		a := gate.accepted(t, "["+spikeClientV6+"]:"+port)
		if a.local != "["+spikeServerV6+"]:80" || a.original != a.local {
			t.Fatalf("accepted %+v, want local and original [%s]:80", a, spikeServerV6)
		}
	})
	t.Run("3_dnat_port_forward_from_wan", func(t *testing.T) {
		lab.install(t, spikeVariant{ready: true})
		port, reply := lab.exchange(t, lab.wan, spikeWANRouter, spikeForwardPort, "t3")
		if want := "peer=" + spikeWANV4 + " msg=via-gate t3"; reply != want {
			t.Fatalf("reply %q, want %q", reply, want)
		}
		a := gate.accepted(t, spikeWANV4+":"+port)
		if a.local != spikeServerV4+":80" || a.original != fmt.Sprintf("%s:%d", spikeWANRouter, spikeForwardPort) {
			t.Fatalf("accepted %+v, want local %s:80 and original %s:%d", a, spikeServerV4, spikeWANRouter, spikeForwardPort)
		}
	})
	t.Run("3_dnat_hairpin_needs_upstream_masquerade", func(t *testing.T) {
		lab.install(t, spikeVariant{ready: true})
		port, reply := lab.exchange(t, lab.hairpin, spikeWANRouter, spikeForwardPort, "t3h0")
		if a := gate.find(spikeHairpinV4 + ":" + port); a == nil || a.dial == "" || strings.Contains(reply, "via-gate") {
			t.Fatalf("hairpin upstream with the client's address reached the server without masquerade: %+v %q", a, reply)
		}
		t.Logf("hairpin upstream without masquerade: dial %q, client saw %q", gate.find(spikeHairpinV4+":"+port).dial, reply)
		lab.install(t, spikeVariant{ready: true, hairpinMasquerade: true})
		port, reply = lab.exchange(t, lab.hairpin, spikeWANRouter, spikeForwardPort, "t3h")
		if want := "peer=" + spikeLANRouter + " msg=via-gate t3h"; reply != want {
			t.Fatalf("reply %q, want %q", reply, want)
		}
		a := gate.accepted(t, spikeHairpinV4+":"+port)
		if a.local != spikeServerV4+":80" || a.original != fmt.Sprintf("%s:%d", spikeWANRouter, spikeForwardPort) {
			t.Fatalf("accepted %+v", a)
		}
	})
	t.Run("4_fib_egress_in_input", func(t *testing.T) {
		lab.install(t, spikeVariant{ready: true})
		names := []string{"in_syn", "in_fib_egress", "in_fib_lo", "in_fib_mark_lo", "in_fib_iif"}
		before := map[string]uint64{}
		for _, n := range names {
			before[n] = lab.counter(t, "", "gate_spike", n)
		}
		if _, reply := lab.exchange(t, lab.client, spikeServerV4, 80, "t4"); !strings.HasSuffix(reply, "via-gate t4") {
			t.Fatalf("reply %q", reply)
		}
		delta := map[string]uint64{}
		for _, n := range names {
			delta[n] = lab.counter(t, "", "gate_spike", n) - before[n]
		}
		t.Logf("marked SYN in INPUT: %v", delta)
		if delta["in_syn"] != 1 || delta["in_fib_egress"] != 1 || delta["in_fib_lo"] != 0 {
			t.Fatalf("fib daddr oifname in INPUT did not resolve the real egress: %v", delta)
		}
		if delta["in_fib_mark_lo"] != 0 || delta["in_fib_iif"] != 0 {
			t.Fatalf("mark/iif fib forms changed meaning: %v", delta)
		}
	})
	t.Run("5_masquerade_selected_by_so_mark", func(t *testing.T) {
		lab.install(t, spikeVariant{ready: true})
		gate.zoneOverride.Store(spikeMasqueradeZone)
		defer gate.zoneOverride.Store(0)
		for _, c := range []struct{ server, want string }{{spikeServerV4, spikeLANRouter}, {spikeServerV6, spikeLANRouterV6}} {
			_, reply := lab.exchange(t, lab.client, c.server, 80, "t5")
			if want := "peer=" + c.want + " msg=via-gate t5"; reply != want {
				t.Fatalf("reply %q, want %q", reply, want)
			}
		}
	})
	t.Run("6_tracked_established_connection_untouched", func(t *testing.T) {
		// containd's policy always holds ct rules, so a connection that
		// predates the gate is known to connection tracking.
		lab.nftIn(t, "", "add table inet gate_baseline\nadd chain inet gate_baseline forward { type filter hook forward priority filter - 1; }\nadd rule inet gate_baseline forward ct state established accept\n")
		t.Cleanup(func() { lab.run(t, "nft", "delete", "table", "inet", "gate_baseline") })
		c := lab.connect(t, lab.client, spikeServerV4, 80)
		lab.install(t, spikeVariant{ready: true})
		if reply := c.exchange(t, "t6"); reply != "peer="+spikeClientV4+" msg=t6" {
			t.Fatalf("pre-existing connection changed: %q", reply)
		}
		if a := gate.find(spikeClientV4 + ":" + c.port); a != nil {
			t.Fatalf("pre-existing connection diverted: %+v", a)
		}
	})
	t.Run("6_untracked_established_connection_untouched", func(t *testing.T) {
		// Without any ct rule the connection is unknown to connection
		// tracking, which picks its next packet up as "new".
		c := lab.connect(t, lab.client, spikeServerV4, 80)
		lab.install(t, spikeVariant{ready: true})
		if reply := c.exchange(t, "t6"); reply != "peer="+spikeClientV4+" msg=t6" {
			t.Fatalf("pre-existing connection changed: %q", reply)
		}
		if a := gate.find(spikeClientV4 + ":" + c.port); a != nil {
			t.Fatalf("pre-existing connection diverted: %+v", a)
		}
		if _, reply := lab.exchange(t, lab.client, spikeServerV4, 80, "t6n"); reply != "peer="+spikeClientV4+" msg=via-gate t6n" {
			t.Fatalf("new connection after install: %q", reply)
		}
	})
	t.Run("7_local_service_stays_local_under_rp_filter", func(t *testing.T) {
		for _, dev := range []string{"all", "gs0", "gs2", "gsbr"} {
			if v := lab.sysctl(t, "net/ipv4/conf/"+dev+"/rp_filter"); v != "1" {
				t.Fatalf("rp_filter on %s is %q", dev, v)
			}
		}
		lab.install(t, spikeVariant{ready: true})
		n := gate.count()
		port, reply := lab.exchange(t, lab.client, spikeClientRouter, 8080, "t7")
		if want := "peer=" + spikeClientV4 + " msg=local t7"; reply != want {
			t.Fatalf("reply %q, want %q", reply, want)
		}
		if gate.count() != n || gate.find(spikeClientV4+":"+port) != nil {
			t.Fatal("local service connection reached the gate")
		}
	})
	t.Run("8_not_ready_resets_without_leaking", func(t *testing.T) {
		lab.install(t, spikeVariant{ready: false})
		before := lab.counter(t, lab.server, "probe", "syn")
		n := gate.count()
		c := lab.connect(t, lab.client, spikeServerV4, 80)
		if c.err != "error 111" {
			t.Fatalf("connect: %q, want ECONNREFUSED", c.err)
		}
		if got := lab.counter(t, lab.server, "probe", "syn"); got != before {
			t.Fatalf("SYN leaked to the server: %d -> %d", before, got)
		}
		if gate.count() != n {
			t.Fatal("gate accepted a connection while not ready")
		}
	})
}

const (
	spikeClientV4     = "198.18.50.2"
	spikeClientV6     = "fd18:50::2"
	spikeClientRouter = "198.18.50.1"
	spikeServerV4     = "198.18.60.2"
	spikeServerV6     = "fd18:60::2"
	spikeLANRouter    = "198.18.60.1"
	spikeLANRouterV6  = "fd18:60::1"
	spikeHairpinV4    = "198.18.60.3"
	spikeWANV4        = "198.18.70.2"
	spikeWANRouter    = "198.18.70.1"
	spikeForwardPort  = 18000
	spikeListenPort   = 18100
	spikeTable        = 104010

	spikeGateCT   = 0x00100000 // ct mark: the connection is gated (client leg)
	spikeUpCT     = 0x00200000 // ct mark: upstream leg of the gate, copied from the dialer's mark in OUTPUT
	spikeLocal    = 0x00400000 // packet mark: policy-route to the local table
	spikeUp       = 0x00800000 // dialer SO_MARK bit; the low byte carries the ingress zone index
	spikeZoneMask = 0x000000ff

	spikeMasqueradeZone = 5
	spikeHairpinZone    = 3
)

type spikeVariant struct {
	ready             bool
	hairpinMasquerade bool
}

// ruleset is the steering recipe under test. The `socket` expression is
// unavailable on this kernel; see TestGateSteeringKernel. Selection
// requires a SYN, not only `ct state new`: connection tracking also
// reports "new" for a mid-stream packet of a connection it has not seen
// (nf_conntrack_tcp_loose), and TPROXY would hand that packet to the
// listener, which answers it with a reset.
func (v spikeVariant) ruleset() string {
	hex := func(n uint32) string { return fmt.Sprintf("0x%08x", n) }
	admit := "ct mark set ct mark | " + hex(spikeGateCT) + " tproxy to :" + strconv.Itoa(spikeListenPort) + " meta mark set meta mark | " + hex(spikeLocal) + " accept"
	if !v.ready {
		admit = "reject with tcp reset"
	}
	hairpin := ""
	if v.hairpinMasquerade {
		hairpin = "    meta mark & " + hex(spikeUp|spikeZoneMask) + " == " + hex(spikeUp|spikeHairpinZone) + " oifname \"gsbr\" masquerade;\n"
	}
	marked := "meta mark & " + hex(spikeLocal) + " == " + hex(spikeLocal) + " tcp dport 80 tcp flags & (syn | ack) == syn"
	r := strings.NewReplacer(
		"WAN_ROUTER", spikeWANRouter, "FORWARD_PORT", strconv.Itoa(spikeForwardPort), "SERVER_V4", spikeServerV4,
		"UP_CT", hex(spikeUpCT), "LOCAL", hex(spikeLocal), "GATE_CT", hex(spikeGateCT), "LISTEN", strconv.Itoa(spikeListenPort),
		"ADMIT", admit, "UP_BIT", hex(spikeUp), "MARKED", marked,
		"UP_MASK", hex(spikeUp|spikeZoneMask), "UP_MASQ", hex(spikeUp|spikeMasqueradeZone), "HAIRPIN\n", hairpin,
	)
	return r.Replace(`table inet gate_spike {
  counter fwd_syn {}
  counter in_syn {}
  counter in_fib_egress {}
  counter in_fib_lo {}
  counter in_fib_mark_lo {}
  counter in_fib_iif {}
  chain dstnat {
    type nat hook prerouting priority dstnat; policy accept;
    iifname { "gs2", "gs0", "gsbr" } ip daddr WAN_ROUTER tcp dport FORWARD_PORT dnat ip to SERVER_V4:80;
  }
  chain gate_pre {
    type filter hook prerouting priority -90; policy accept;
    ct mark & UP_CT == UP_CT ct direction reply meta mark set meta mark | LOCAL accept;
    fib daddr type local return;
    meta l4proto tcp ct mark & GATE_CT == GATE_CT tproxy to :LISTEN meta mark set meta mark | LOCAL accept;
    ct state new tcp flags & (syn | ack) == syn iifname { "gs0", "gs2", "gsbr" } fib daddr oifname { "gsbr", "gs0" } tcp dport { 80, 8080 } ADMIT;
  }
  chain gate_out {
    type filter hook output priority mangle; policy accept;
    meta mark & UP_BIT == UP_BIT ct mark set ct mark | UP_CT;
  }
  chain input {
    type filter hook input priority filter; policy accept;
    MARKED counter name "in_syn";
    MARKED fib daddr oifname "gsbr" counter name "in_fib_egress";
    MARKED fib daddr oifname "lo" counter name "in_fib_lo";
    MARKED fib daddr . mark oifname "lo" counter name "in_fib_mark_lo";
    MARKED fib daddr . iif oifname "gsbr" counter name "in_fib_iif";
  }
  chain forward {
    type filter hook forward priority filter; policy accept;
    tcp dport 80 tcp flags & (syn | ack) == syn counter name "fwd_syn";
  }
  chain srcnat {
    type nat hook postrouting priority srcnat; policy accept;
    meta mark & UP_MASK == UP_MASQ oifname "gsbr" masquerade;
HAIRPIN
  }
}
`)
}

// spikeLab is the topology around this namespace: client (gs0, zone 1),
// WAN (gs2, zone 2) and a bridged LAN gsbr (zone 3) holding the server and
// the hairpin client.
type spikeLab struct {
	ctx                          context.Context
	client, server, hairpin, wan string
	installed                    bool
}

func newSpikeLab(t *testing.T) *spikeLab {
	t.Helper()
	if os.Getenv("CONTAIND_NETNS_KERNEL_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("requires CONTAIND_NETNS_KERNEL_TEST=1 in a disposable Linux container with NET_ADMIN, NET_RAW and SYS_ADMIN; see scripts/gate-spike/run.sh")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	t.Cleanup(cancel)
	lab := &spikeLab{ctx: ctx, client: "gsclient", server: "gsserver", hairpin: "gshair", wan: "gswan"}
	t.Logf("kernel %s", lab.run(t, "uname", "-r"))
	// /proc/sys is read-only in an unprivileged container: the runner sets
	// these with docker run --sysctl.
	for _, s := range []string{"net/ipv4/ip_forward", "net/ipv6/conf/all/forwarding", "net/ipv4/conf/all/rp_filter", "net/ipv4/conf/default/rp_filter"} {
		lab.requireSysctl(t, s, "1")
	}
	for _, s := range []string{"net/bridge/bridge-nf-call-iptables", "net/bridge/bridge-nf-call-ip6tables"} {
		lab.requireSysctl(t, s, "0")
	}
	lab.run(t, "ip", "link", "add", "gsbr", "type", "bridge")
	t.Cleanup(func() { lab.run(t, "ip", "link", "del", "gsbr") })
	lab.run(t, "ip", "addr", "add", spikeLANRouter+"/24", "dev", "gsbr")
	lab.run(t, "ip", "-6", "addr", "add", spikeLANRouterV6+"/64", "dev", "gsbr", "nodad")
	lab.run(t, "ip", "link", "set", "gsbr", "up")
	type leaf struct {
		ns, dev, peer, host4, host6, addr4, addr6, gw4, gw6, master string
	}
	for _, l := range []leaf{
		{lab.client, "gs0", "gsp0", spikeClientRouter + "/24", "fd18:50::1/64", spikeClientV4 + "/24", spikeClientV6 + "/64", spikeClientRouter, "fd18:50::1", ""},
		{lab.server, "gs1", "gsp1", "", "", spikeServerV4 + "/24", spikeServerV6 + "/64", spikeLANRouter, spikeLANRouterV6, "gsbr"},
		{lab.hairpin, "gs3", "gsp3", "", "", spikeHairpinV4 + "/24", "", spikeLANRouter, "", "gsbr"},
		{lab.wan, "gs2", "gsp2", spikeWANRouter + "/24", "", spikeWANV4 + "/24", "", spikeWANRouter, "", ""},
	} {
		lab.run(t, "ip", "netns", "add", l.ns)
		t.Cleanup(func() { lab.run(t, "ip", "netns", "del", l.ns) })
		lab.run(t, "ip", "link", "add", l.dev, "type", "veth", "peer", "name", l.peer)
		t.Cleanup(func() { lab.run(t, "ip", "link", "del", l.dev) })
		lab.run(t, "ip", "link", "set", l.peer, "netns", l.ns)
		if l.master != "" {
			lab.run(t, "ip", "link", "set", l.dev, "master", l.master)
		}
		if l.host4 != "" {
			lab.run(t, "ip", "addr", "add", l.host4, "dev", l.dev)
		}
		if l.host6 != "" {
			lab.run(t, "ip", "-6", "addr", "add", l.host6, "dev", l.dev, "nodad")
		}
		lab.run(t, "ip", "link", "set", l.dev, "up")
		lab.run(t, "ip", "-n", l.ns, "addr", "add", l.addr4, "dev", l.peer)
		lab.run(t, "ip", "-n", l.ns, "link", "set", l.peer, "up")
		lab.run(t, "ip", "-n", l.ns, "link", "set", "lo", "up")
		lab.run(t, "ip", "-n", l.ns, "route", "add", "default", "via", l.gw4)
		if l.addr6 != "" {
			lab.run(t, "ip", "-n", l.ns, "-6", "addr", "add", l.addr6, "dev", l.peer, "nodad")
			lab.run(t, "ip", "-n", l.ns, "-6", "route", "add", "default", "via", l.gw6)
		}
	}
	for _, dev := range []string{"gs0", "gs2", "gsbr"} {
		lab.requireSysctl(t, "net/ipv4/conf/"+dev+"/rp_filter", "1")
	}
	// Routing neighbours the gate must coexist with: a management pin at
	// priority 1 for a client that may also manage containd, and a user
	// policy rule at priority 2 that routes the client's traffic to the LAN
	// through its own table. The gate's local rule must precede the latter.
	lab.run(t, "ip", "route", "add", spikeClientV4+"/32", "dev", "gs0", "table", "104000")
	lab.run(t, "ip", "rule", "add", "priority", "1", "from", spikeClientRouter, "to", spikeClientV4, "lookup", "104000")
	lab.run(t, "ip", "route", "add", "198.18.60.0/24", "dev", "gsbr", "table", "201")
	lab.run(t, "ip", "rule", "add", "priority", "2", "from", "198.18.50.0/24", "to", "198.18.60.0/24", "lookup", "201")
	t.Cleanup(func() {
		lab.run(t, "ip", "rule", "del", "priority", "2", "from", "198.18.50.0/24", "to", "198.18.60.0/24", "lookup", "201")
		lab.run(t, "ip", "rule", "del", "priority", "1", "from", spikeClientRouter, "to", spikeClientV4, "lookup", "104000")
	})
	return lab
}

func (l *spikeLab) run(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.CommandContext(l.ctx, args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %v: %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func (l *spikeLab) sysctl(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile("/proc/sys/" + path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}

func (l *spikeLab) requireSysctl(t *testing.T, path, value string) {
	t.Helper()
	if got := l.sysctl(t, path); got != value {
		t.Fatalf("%s is %q, want %q (set it with docker run --sysctl)", path, got, value)
	}
}

// nftIn loads an nft script in namespace ns ("" is this namespace).
func (l *spikeLab) nftIn(t *testing.T, ns, script string) {
	t.Helper()
	args := []string{"nft", "-f", "-"}
	if ns != "" {
		args = append([]string{"ip", "netns", "exec", ns}, args...)
	}
	cmd := exec.CommandContext(l.ctx, args[0], args[1:]...)
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft: %v: %s\n%s", err, out, script)
	}
}

// install replaces the steering ruleset and policy routes with variant v;
// the calling (sub)test's end removes them.
func (l *spikeLab) install(t *testing.T, v spikeVariant) {
	t.Helper()
	l.uninstall(t)
	l.nftIn(t, "", v.ruleset())
	for _, family := range []string{"-4", "-6"} {
		l.run(t, "ip", family, "rule", "add", "priority", "1", "fwmark", fmt.Sprintf("0x%08x/0x%08x", spikeLocal, spikeLocal), "lookup", strconv.Itoa(spikeTable))
		l.run(t, "ip", family, "route", "add", "local", "default", "dev", "lo", "table", strconv.Itoa(spikeTable))
	}
	l.installed = true
	t.Cleanup(func() { l.uninstall(t) })
}

func (l *spikeLab) uninstall(t *testing.T) {
	t.Helper()
	if !l.installed {
		return
	}
	l.installed = false
	l.run(t, "nft", "delete", "table", "inet", "gate_spike")
	for _, family := range []string{"-4", "-6"} {
		l.run(t, "ip", family, "rule", "del", "priority", "1", "fwmark", fmt.Sprintf("0x%08x/0x%08x", spikeLocal, spikeLocal), "lookup", strconv.Itoa(spikeTable))
		l.run(t, "ip", family, "route", "flush", "table", strconv.Itoa(spikeTable))
	}
}

var spikeCounterPackets = regexp.MustCompile(`packets (\d+)`)

// counter reads a named nft counter in namespace ns ("" is this namespace).
func (l *spikeLab) counter(t *testing.T, ns, table, name string) uint64 {
	t.Helper()
	args := []string{"nft", "list", "counter", "inet", table, name}
	if ns != "" {
		args = append([]string{"ip", "netns", "exec", ns}, args...)
	}
	m := spikeCounterPackets.FindStringSubmatch(l.run(t, args...))
	if m == nil {
		t.Fatalf("counter %s/%s not listed", table, name)
	}
	n, err := strconv.ParseUint(m[1], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

const spikeServerProgram = `import socket, sys
addr, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET6 if ':' in addr else socket.AF_INET)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((addr, port)); s.listen(); print('ready', flush=True)
while True:
    c, a = s.accept()
    line = c.makefile('rb').readline().decode().rstrip('\n')
    c.sendall(('peer=%s msg=%s\n' % (a[0], line)).encode()); c.close()
`

// serve runs a line server in namespace ns on addr:port that answers each
// line with the peer address it saw and the line. It lives until the test
// that started it ends.
func (l *spikeLab) serve(t *testing.T, ns, addr string, port int) {
	t.Helper()
	server := exec.CommandContext(l.ctx, "ip", "netns", "exec", ns, "python3", "-u", "-c", spikeServerProgram, addr, strconv.Itoa(port))
	stdout, err := server.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	server.Stderr = os.Stderr
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })
	if !bufio.NewScanner(stdout).Scan() {
		t.Fatal("server did not start")
	}
}

// serveLocal runs the same line server in this namespace with Go, tagging
// its answers "local": it stands in for management.
func (l *spikeLab) serveLocal(t *testing.T, addr string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp4", net.JoinHostPort(addr, strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				line, _ := bufio.NewReader(c).ReadString('\n')
				host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
				fmt.Fprintf(c, "peer=%s msg=local %s\n", host, strings.TrimSuffix(line, "\n"))
			}()
		}
	}()
}

const spikeClientProgram = `import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET)
s.settimeout(4)
try:
    s.connect((host, port))
except OSError as e:
    print('error', e.errno, flush=True); sys.exit(0)
print('connected', s.getsockname()[1], flush=True)
data = b''
try:
    s.sendall(sys.stdin.readline().encode())
    while not data.endswith(b'\n'):
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
except OSError as e:
    print('error', e.errno, flush=True); sys.exit(0)
print('reply', data.decode().rstrip('\n'), flush=True)
`

// spikeClient is one TCP connection held open by a Python process in a
// namespace: it connects first and sends its line only on exchange.
type spikeClient struct {
	stdin io.WriteCloser
	out   *bufio.Scanner
	port  string // local port when connected
	err   string // "error <errno>" when the connect failed
}

func (l *spikeLab) connect(t *testing.T, ns, addr string, port int) *spikeClient {
	t.Helper()
	cmd := exec.CommandContext(l.ctx, "ip", "netns", "exec", ns, "python3", "-u", "-c", spikeClientProgram, addr, strconv.Itoa(port))
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	c := &spikeClient{stdin: stdin, out: bufio.NewScanner(stdout)}
	if !c.out.Scan() {
		t.Fatalf("client %s -> %s:%d produced no output", ns, addr, port)
	}
	line := c.out.Text()
	switch {
	case strings.HasPrefix(line, "connected "):
		c.port = strings.TrimPrefix(line, "connected ")
	case strings.HasPrefix(line, "error "):
		c.err = line
	default:
		t.Fatalf("client: %q", line)
	}
	return c
}

// exchange sends line and returns the server's answer: "" at EOF, or
// "error <errno>" when the connection failed.
func (c *spikeClient) exchange(t *testing.T, line string) string {
	t.Helper()
	if c.err != "" {
		t.Fatalf("exchange on failed connection: %s", c.err)
	}
	if _, err := io.WriteString(c.stdin, line+"\n"); err != nil {
		t.Fatal(err)
	}
	if !c.out.Scan() {
		t.Fatal("client produced no reply line")
	}
	return strings.TrimPrefix(c.out.Text(), "reply ")
}

// exchange connects from ns to addr:port, sends line and returns the
// connection's local port and the answer.
func (l *spikeLab) exchange(t *testing.T, ns, addr string, port int, line string) (string, string) {
	t.Helper()
	c := l.connect(t, ns, addr, port)
	if c.err != "" {
		t.Fatalf("connect %s -> %s:%d: %s", ns, addr, port, c.err)
	}
	return c.port, c.exchange(t, line)
}

// spikeGate is the transparent proxy in this namespace: it accepts gated
// connections, dials the accepted local address with the client's address
// and SO_MARK carrying the ingress zone, and prefixes the forwarded line
// with "via-gate" so that a server's answer shows the path it took.
type spikeGate struct {
	lab          *spikeLab
	zoneOverride atomic.Int32
	mu           sync.Mutex
	accepts      map[string]spikeAccept // by client address
}

type spikeAccept struct {
	local, original string
	dial            string
}

func startSpikeGate(t *testing.T, lab *spikeLab) *spikeGate {
	t.Helper()
	g := &spikeGate{lab: lab, accepts: map[string]spikeAccept{}}
	for _, network := range []string{"tcp4", "tcp6"} {
		lc := net.ListenConfig{Control: func(network, _ string, c syscall.RawConn) error { return spikeControl(c, network, 0) }}
		ln, err := lc.Listen(lab.ctx, network, fmt.Sprintf(":%d", spikeListenPort))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go g.handle(network, c.(*net.TCPConn))
			}
		}()
	}
	return g
}

// spikeControl makes the socket transparent for its family and marks it.
func spikeControl(c syscall.RawConn, network string, mark int) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		if network == "tcp6" {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
		} else {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
		}
		if serr == nil && mark != 0 {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, mark)
		}
	})
	if err != nil {
		return err
	}
	return serr
}

func (g *spikeGate) zone(client net.IP) int {
	if z := g.zoneOverride.Load(); z != 0 {
		return int(z)
	}
	switch {
	case strings.HasPrefix(client.String(), "198.18.50."), strings.HasPrefix(client.String(), "fd18:50:"):
		return 1
	case strings.HasPrefix(client.String(), "198.18.70."):
		return 2
	default:
		return spikeHairpinZone
	}
}

func (g *spikeGate) handle(network string, c *net.TCPConn) {
	defer c.Close()
	client := c.RemoteAddr().(*net.TCPAddr)
	a := spikeAccept{local: c.LocalAddr().String(), original: spikeOriginalDst(c, network)}
	mark := spikeUp | g.zone(client.IP)
	d := net.Dialer{Timeout: 3 * time.Second, LocalAddr: &net.TCPAddr{IP: client.IP}, Control: func(network, _ string, rc syscall.RawConn) error { return spikeControl(rc, network, mark) }}
	up, err := d.DialContext(g.lab.ctx, network, a.local)
	if err != nil {
		a.dial = err.Error()
	}
	g.mu.Lock()
	g.accepts[client.String()] = a
	g.mu.Unlock()
	if err != nil {
		return
	}
	defer up.Close()
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return
	}
	if _, err := io.WriteString(up, "via-gate "+line); err != nil {
		return
	}
	reply, _ := bufio.NewReader(up).ReadString('\n')
	_, _ = io.WriteString(c, reply)
}

// spikeOriginalDst returns the connection's destination before DNAT from
// connection tracking (SO_ORIGINAL_DST), or the error.
func spikeOriginalDst(c *net.TCPConn, network string) string {
	raw, err := c.SyscallConn()
	if err != nil {
		return err.Error()
	}
	var result string
	if err := raw.Control(func(fd uintptr) {
		if network == "tcp6" {
			var sa unix.RawSockaddrInet6
			n := uint32(unsafe.Sizeof(sa))
			if _, _, e := unix.Syscall6(unix.SYS_GETSOCKOPT, fd, unix.SOL_IPV6, unix.SO_ORIGINAL_DST, uintptr(unsafe.Pointer(&sa)), uintptr(unsafe.Pointer(&n)), 0); e != 0 {
				result = "getsockopt: " + e.Error()
				return
			}
			result = net.JoinHostPort(net.IP(sa.Addr[:]).String(), spikePort(sa.Port))
			return
		}
		var sa unix.RawSockaddrInet4
		n := uint32(unsafe.Sizeof(sa))
		if _, _, e := unix.Syscall6(unix.SYS_GETSOCKOPT, fd, unix.SOL_IP, unix.SO_ORIGINAL_DST, uintptr(unsafe.Pointer(&sa)), uintptr(unsafe.Pointer(&n)), 0); e != 0 {
			result = "getsockopt: " + e.Error()
			return
		}
		result = net.JoinHostPort(net.IP(sa.Addr[:]).String(), spikePort(sa.Port))
	}); err != nil {
		return err.Error()
	}
	return result
}

// spikePort formats a network-order sockaddr port.
func spikePort(p uint16) string {
	return strconv.Itoa(int(p>>8 | (p&0xff)<<8))
}

// accepted returns the gate's record for the client address, waiting
// briefly for the handler to store it.
func (g *spikeGate) accepted(t *testing.T, client string) spikeAccept {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if a := g.find(client); a != nil {
			if a.dial != "" {
				t.Fatalf("gate accepted %s but the upstream dial failed: %s", client, a.dial)
			}
			return *a
		}
		if time.Now().After(deadline) {
			t.Fatalf("gate did not accept a connection from %s", client)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (g *spikeGate) find(client string) *spikeAccept {
	g.mu.Lock()
	defer g.mu.Unlock()
	if a, ok := g.accepts[client]; ok {
		return &a
	}
	return nil
}

func (g *spikeGate) count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.accepts)
}
