// SPDX-License-Identifier: Apache-2.0
//go:build linux

package enforce

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// The bridge's router namespace enables br_netfilter independently of the
// runner, so other kernel tests retain their own bridge-netfilter settings.
func testAccountingBridgeNetfilter(t *testing.T) {
	lab := newNetnsLab(t, "acb", 180, 90*time.Second)
	const router = "accounting_bridge"
	lab.run(t, "ip", "netns", "add", router)
	// Remove the router before newNetnsLab's device cleanups; move its veths
	// back first so those cleanups can delete their own links normally.
	t.Cleanup(func() {
		for _, dev := range []string{"acb0", "acb1"} {
			lab.run(t, "ip", "-n", router, "link", "set", dev, "nomaster")
			lab.run(t, "ip", "-n", router, "link", "set", dev, "netns", fmt.Sprint(os.Getpid()))
		}
		lab.run(t, "ip", "netns", "del", router)
	})
	run := func(args ...string) string {
		t.Helper()
		return lab.run(t, append([]string{"ip", "netns", "exec", router}, args...)...)
	}
	run("ip", "link", "add", "br0", "type", "bridge")
	run("ip", "link", "set", "br0", "up")
	for _, dev := range []string{"acb0", "acb1"} {
		lab.run(t, "ip", "link", "set", dev, "netns", router)
		run("ip", "addr", "flush", "dev", dev)
		run("ip", "link", "set", dev, "master", "br0")
		run("ip", "link", "set", dev, "up")
	}
	lab.run(t, "ip", "-n", lab.target, "addr", "flush", "dev", "acbp1")
	lab.run(t, "ip", "-n", lab.target, "addr", "add", "198.18.180.3/24", "dev", "acbp1")
	parentSetting, err := os.ReadFile("/proc/sys/net/bridge/bridge-nf-call-iptables")
	if err != nil {
		t.Fatal(err)
	}
	// Docker masks /proc/sys read-only. ip netns exec already supplies a
	// private mount namespace; mount fresh procfs there for this namespace's
	// sysctl write, without remounting or changing the runner's /proc.
	run("sh", "-ec", "mount -t proc proc /proc && sysctl -w net.bridge.bridge-nf-call-iptables=1")
	if got := strings.TrimSpace(run("cat", "/proc/sys/net/bridge/bridge-nf-call-iptables")); got != "1" {
		t.Fatalf("bridge netfilter: %q", got)
	}
	t.Cleanup(func() {
		current, err := os.ReadFile("/proc/sys/net/bridge/bridge-nf-call-iptables")
		if err != nil || string(current) != string(parentSetting) {
			t.Fatalf("runner's bridge setting changed: %q, %v", current, err)
		}
	})
	// Bridge member devices are parents, so the applied leaf map contains
	// only the bridge and the other zone's device (see telemetry membership tests).
	a := NewAccounting("containd", map[string]string{"br0": "lan", "unused": "outside"})
	if len(a.Pairs) != 2 {
		t.Fatalf("non-leaf devices acquired counters: %+v", a.Pairs)
	}
	script, err := a.Script()
	if err != nil {
		t.Fatal(err)
	}
	// Positive control proves that these bridged UDP packets really traverse
	// inet forward, rather than passing only because bridge netfilter is off.
	script += `table inet accounting_bridge_control {
 counter seen { }
 chain forward { type filter hook forward priority 110; policy accept;
  iifname "br0" oifname "br0" meta l4proto udp counter name seen
 }
}
`
	cmd := exec.CommandContext(lab.ctx, "ip", "netns", "exec", router, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("install accounting: %v: %s", err, out)
	}
	accountingUDPServer(t, lab, "198.18.180.3", "AF_INET")
	lab.run(t, "ip", "netns", "exec", lab.client, "python3", "-c", `import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2); s.connect(("198.18.180.3",18010))
for i in range(3):
 s.send(b"ping"); assert s.recv(128)==b"198.18.180.2:ping"
`)
	values, err := parseCounters([]byte(run("nft", "-j", "list", "counters", "table", "inet", a.Table)))
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 2 {
		t.Fatalf("cross-zone counters: %+v", values)
	}
	for name, v := range values {
		if v.Packets != 0 || v.Bytes != 0 {
			t.Fatalf("bridged L2 charged conduit %s: %+v", name, v)
		}
	}
	control, err := parseCounters([]byte(run("nft", "-j", "list", "counters", "table", "inet", "accounting_bridge_control")))
	if err != nil {
		t.Fatal(err)
	}
	if control["seen"].Packets != 6 {
		t.Fatalf("bridge netfilter not exercised: %+v", control)
	}
}
