// SPDX-License-Identifier: Apache-2.0
//go:build linux

package enforce

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// Real packets through the forward chain for RESET, RATE_LIMIT and TAG,
// on IPv4 and IPv6, with the rule counters read back through nft. The
// client sits behind act0 (198.18.130.2, fd00:130::2), the target behind
// act1 (198.18.140.2, fd00:140::2).
const (
	actTarget4 = "198.18.140.2"
	actTarget6 = "fd00:140::2"
)

func newActionLab(t *testing.T) *netnsLab {
	t.Helper()
	lab := newNetnsLab(t, "act", 130, 2*time.Minute)
	lab.run(t, "ip", "-n", lab.client, "route", "add", "198.18.140.0/24", "via", "198.18.130.1")
	lab.run(t, "ip", "-n", lab.target, "route", "add", "198.18.130.0/24", "via", "198.18.140.1")
	for _, p := range []string{"/proc/sys/net/ipv6/conf/all/disable_ipv6", "/proc/sys/net/ipv6/conf/default/disable_ipv6"} {
		if err := os.WriteFile(p, []byte("0"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1"), 0600); err != nil {
		t.Fatal(err)
	}
	for i, ns := range []string{lab.client, lab.target} {
		net := 130 + i*10
		lab.run(t, "ip", "addr", "add", fmt.Sprintf("fd00:%d::1/64", net), "dev", fmt.Sprintf("act%d", i), "nodad")
		lab.run(t, "ip", "-n", ns, "addr", "add", fmt.Sprintf("fd00:%d::2/64", net), "dev", fmt.Sprintf("actp%d", i), "nodad")
	}
	lab.run(t, "ip", "-n", lab.client, "-6", "route", "add", "fd00:140::/64", "via", "fd00:130::1")
	lab.run(t, "ip", "-n", lab.target, "-6", "route", "add", "fd00:130::/64", "via", "fd00:140::1")
	// Resolve the neighbours of both paths before any burst, while
	// nothing filters yet: a burst queued behind neighbour discovery would
	// arrive after the test looks.
	for _, addr := range []string{actTarget4, actTarget6} {
		lab.run(t, "ip", "netns", "exec", lab.client, "ping", "-c", "1", "-W", "5", addr)
	}
	return lab
}

// recorder runs a server in the target namespace that appends one line per
// TCP connection or UDP datagram it receives to a file; echo makes the UDP
// server answer each datagram.
func (l *netnsLab) recorder(t *testing.T, proto, addr string, port int, echo bool) func() int {
	t.Helper()
	path := filepath.Join(t.TempDir(), "received")
	answer := "pass"
	if echo {
		answer = "s.sendto(d,a)"
	}
	body := fmt.Sprintf(`import socket
f=open(%q,'a',buffering=1)
s=socket.socket(%s, socket.SOCK_STREAM if %q=='tcp' else socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((%q,%d))
if %q=='tcp': s.listen()
print('ready',flush=True)
while True:
 if %q=='tcp':
  c,a=s.accept(); f.write('conn\n'); c.close()
 else:
  d,a=s.recvfrom(2048); f.write('dgram\n'); %s
`, path, socketFamily(addr), proto, addr, port, proto, proto, answer)
	server := exec.CommandContext(l.ctx, "ip", "netns", "exec", l.target, "python3", "-u", "-c", body)
	stdout, err := server.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })
	if !bufio.NewScanner(stdout).Scan() {
		t.Fatal("recorder did not start")
	}
	return func() int {
		data, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		return strings.Count(string(data), "\n")
	}
}

// runClient runs a Python snippet in the client namespace and returns its
// trimmed output.
func (l *netnsLab) runClient(t *testing.T, body string) string {
	t.Helper()
	out, err := exec.CommandContext(l.ctx, "ip", "netns", "exec", l.client, "python3", "-c", body).CombinedOutput()
	if err != nil {
		t.Fatalf("client: %v: %s", err, out)
	}
	return strings.TrimSpace(string(out))
}

// counts reads the rule counters of the applied snapshot.
func (l *netnsLab) counts(t *testing.T, c *Compiler, snap *rules.Snapshot) map[string]RuleCount {
	t.Helper()
	counters, err := NewNftApplier().ReadCounters(l.ctx, c.PolicyTable())
	if err != nil {
		t.Fatal(err)
	}
	list, err := RuleCounts(snap, counters)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]RuleCount{}
	for _, rc := range list {
		out[rc.RuleID] = rc
	}
	return out
}

func socketFamily(addr string) string {
	if strings.Contains(addr, ":") {
		return "socket.AF_INET6"
	}
	return "socket.AF_INET"
}

func TestActionsKernel(t *testing.T) {
	lab := newActionLab(t)

	// RESET rejects TCP with a reset and anything else with ICMP or
	// ICMPv6 administratively prohibited; the target never sees the
	// connection or the payload.
	t.Run("reset", func(t *testing.T) {
		snap := &rules.Snapshot{Default: rules.ActionDeny, Firewall: []rules.Entry{{
			ID: "reset", Action: rules.ActionReset,
			Protocols: []rules.Protocol{{Name: "tcp", Port: "18101"}, {Name: "udp", Port: "18102"}},
		}}}
		c := NewCompiler()
		lab.apply(t, c, snap)
		for _, tc := range []struct{ addr, icmp string }{{actTarget4, "3 13"}, {actTarget6, "1 1"}} {
			tcpSeen := lab.recorder(t, "tcp", tc.addr, 18101, false)
			udpSeen := lab.recorder(t, "udp", tc.addr, 18102, false)
			out := lab.runClient(t, fmt.Sprintf(`import socket,time
s=socket.socket(%s); s.settimeout(3); t=time.monotonic()
try:
 s.connect((%q,18101)); print('connected')
except ConnectionRefusedError:
 print('reset', round(time.monotonic()-t, 1))
`, socketFamily(tc.addr), tc.addr))
			if out != "reset 0.0" {
				t.Fatalf("%s TCP: %q, want an immediate reset", tc.addr, out)
			}
			level, recverr := "socket.IPPROTO_IP", 11 // IP_RECVERR
			if strings.Contains(tc.addr, ":") {
				level, recverr = "socket.IPPROTO_IPV6", 25 // IPV6_RECVERR
			}
			out = lab.runClient(t, fmt.Sprintf(`import socket,struct
s=socket.socket(%s, socket.SOCK_DGRAM); s.setsockopt(%s, %d, 1); s.settimeout(3)
s.connect((%q,18102)); s.send(b'payload')
try:
 s.recv(64)
except OSError:
 pass
_,anc,_,_=s.recvmsg(64, 1024, socket.MSG_ERRQUEUE)
for lvl,typ,data in anc:
 errno_,origin,etype,ecode=struct.unpack('=IBBB',data[:7]); print(etype, ecode)
`, socketFamily(tc.addr), level, recverr, tc.addr))
			if out != tc.icmp {
				t.Fatalf("%s UDP: ICMP type/code %q, want %q (destination unreachable, administratively prohibited)", tc.addr, out, tc.icmp)
			}
			time.Sleep(200 * time.Millisecond)
			t.Logf("%s: TCP reset at once, ICMP type/code %s", tc.addr, out)
			if n, m := tcpSeen(), udpSeen(); n != 0 || m != 0 {
				t.Fatalf("%s: target received %d connections and %d datagrams", tc.addr, n, m)
			}
		}
		if rc := lab.counts(t, c, snap)["reset"]; rc.Packets < 4 || rc.ExcessDrops != nil {
			t.Fatalf("reset counter = %+v, want every rejected packet", rc)
		}
	})

	// RATE_LIMIT drops a burst's excess per 5-tuple, counted exactly, on
	// IPv4 and IPv6; the ALLOW still decides the packets under the limit.
	t.Run("rate limit burst", func(t *testing.T) {
		snap := &rules.Snapshot{Default: rules.ActionDeny, Firewall: []rules.Entry{
			{ID: "allow", Action: rules.ActionAllow, Protocols: []rules.Protocol{{Name: "udp", Port: "18103"}}},
			{ID: "police", Action: rules.ActionRateLimit, Protocols: []rules.Protocol{{Name: "udp", Port: "18103"}},
				RateLimit: &rules.RateLimit{PacketsPerSecond: 10, Burst: 5}},
		}}
		c := NewCompiler()
		lab.apply(t, c, snap)
		const sent = 40
		var excess uint64
		for _, addr := range []string{actTarget4, actTarget6} {
			seen := lab.recorder(t, "udp", addr, 18103, false)
			out := lab.runClient(t, fmt.Sprintf(`import socket,time
s=socket.socket(%s, socket.SOCK_DGRAM); t=time.monotonic()
for i in range(%d): s.sendto(b'x', (%q,18103))
print(time.monotonic()-t)
`, socketFamily(addr), sent, addr))
			elapsed, err := strconv.ParseFloat(out, 64)
			if err != nil {
				t.Fatal(out)
			}
			time.Sleep(300 * time.Millisecond)
			got := seen()
			if limit := 5 + int(10*elapsed) + 1; got < 5 || got > limit {
				t.Fatalf("%s: target received %d of %d in %.3fs, want 5 to %d", addr, got, sent, elapsed, limit)
			}
			excess += uint64(sent - got)
			t.Logf("%s: %d of %d datagrams passed in %.4fs", addr, got, sent, elapsed)
			rc := lab.counts(t, c, snap)["police"]
			if rc.ExcessDrops == nil || *rc.ExcessDrops != excess {
				t.Fatalf("%s: excess counter = %v, want %d", addr, rc.ExcessDrops, excess)
			}
		}
		counts := lab.counts(t, c, snap)
		t.Logf("counters: %+v; excess drops %d", counts, *counts["police"].ExcessDrops)
		if counts["police"].Packets != 2*sent || counts["allow"].Packets != 2*sent-excess {
			t.Fatalf("counters = %+v, want %d metered and %d allowed", counts, 2*sent, 2*sent-excess)
		}
	})

	// Established traffic is metered too: the meter sits before the
	// established accept.
	t.Run("rate limit established", func(t *testing.T) {
		snap := &rules.Snapshot{Default: rules.ActionDeny, Firewall: []rules.Entry{
			{ID: "allow", Action: rules.ActionAllow, Protocols: []rules.Protocol{{Name: "udp", Port: "18104"}}},
			{ID: "police", Action: rules.ActionRateLimit, Protocols: []rules.Protocol{{Name: "udp", Port: "18104"}},
				RateLimit: &rules.RateLimit{PacketsPerSecond: 10, Burst: 5}},
		}}
		c := NewCompiler()
		lab.apply(t, c, snap)
		seen := lab.recorder(t, "udp", actTarget4, 18104, true)
		out := lab.runClient(t, fmt.Sprintf(`import socket,time
s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2); s.connect((%q,18104))
s.send(b'hello'); assert s.recv(64)==b'hello'
time.sleep(1)
t=time.monotonic()
for i in range(40): s.send(b'x')
print(time.monotonic()-t)
`, actTarget4))
		elapsed, err := strconv.ParseFloat(out, 64)
		if err != nil {
			t.Fatal(out)
		}
		time.Sleep(300 * time.Millisecond)
		got := seen() - 1 // the handshake datagram
		t.Logf("established flow: %d of 40 datagrams passed in %.4fs", got, elapsed)
		if limit := 5 + int(10*elapsed) + 1; got < 5 || got > limit {
			t.Fatalf("established flow: target received %d of 40 in %.3fs, want 5 to %d", got, elapsed, limit)
		}
		if rc := lab.counts(t, c, snap)["police"]; rc.ExcessDrops == nil || *rc.ExcessDrops != uint64(40-got) {
			t.Fatalf("excess counter = %v, want %d", rc.ExcessDrops, 40-got)
		}
	})

	// TAG has no kernel effect: it counts the openers it matches and
	// admits nothing; the ALLOW decides.
	t.Run("tag admits nothing", func(t *testing.T) {
		lab.serveTarget(t, actTarget4, 18105)
		tag := rules.Entry{ID: "tag", Action: rules.ActionTag, Tag: "plc", Protocols: []rules.Protocol{{Name: "tcp", Port: "18105"}}}
		snap := &rules.Snapshot{Default: rules.ActionDeny, Firewall: []rules.Entry{tag}}
		c := NewCompiler()
		lab.apply(t, c, snap)
		if err := lab.probe(actTarget4, 18105, "198.18.130.2"); err == nil {
			t.Fatal("a TAG rule admitted traffic")
		}
		if rc := lab.counts(t, c, snap)["tag"]; rc.Packets == 0 {
			t.Fatal("the TAG rule did not count the opener")
		}
		snap.Firewall = append(snap.Firewall, rules.Entry{ID: "allow", Action: rules.ActionAllow, Protocols: tag.Protocols})
		lab.apply(t, c, snap)
		if err := lab.probe(actTarget4, 18105, "198.18.130.2"); err != nil {
			t.Fatalf("TAG stopped the ALLOW: %v", err)
		}
		if counts := lab.counts(t, c, snap); counts["tag"].Packets != 1 || counts["allow"].Packets != 1 {
			t.Fatalf("counters after one connection = %+v; the counters restart with each apply", counts)
		}
	})
}
