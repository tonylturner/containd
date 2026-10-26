// SPDX-License-Identifier: Apache-2.0
//go:build linux

package enforce

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

func TestNATKernelCustomZoneReturnPath(t *testing.T) {
	if os.Getenv("CONTAIND_NAT_KERNEL_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("requires opt-in disposable Linux namespace, root, NET_ADMIN, SYS_ADMIN, nft, iproute2 and Python")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := func(args ...string) string {
		t.Helper()
		out, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %v: %s", args, err, out)
		}
		return string(out)
	}
	for _, n := range []string{"natclient", "nattarget"} {
		command("ip", "netns", "add", n)
		defer command("ip", "netns", "del", n)
	}
	for i, n := range []string{"natclient", "nattarget"} {
		dev := fmt.Sprintf("nat%d", i)
		peer := fmt.Sprintf("peer%d", i)
		command("ip", "link", "add", dev, "type", "veth", "peer", "name", peer)
		defer command("ip", "link", "del", dev)
		command("ip", "link", "set", peer, "netns", n)
		command("ip", "addr", "add", fmt.Sprintf("198.18.%d.1/24", 10+i*10), "dev", dev)
		command("ip", "link", "set", dev, "up")
		command("ip", "-n", n, "addr", "add", fmt.Sprintf("198.18.%d.2/24", 10+i*10), "dev", peer)
		command("ip", "-n", n, "link", "set", peer, "up")
		command("ip", "-n", n, "link", "set", "lo", "up")
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0600); err != nil {
		t.Fatal(err)
	}
	// The target deliberately has no default route: a successful response proves
	// scoped masquerade supplies the return path, regardless of its zone name.
	server := exec.CommandContext(ctx, "ip", "netns", "exec", "nattarget", "python3", "-u", "-c", `import socket
s=socket.socket(); s.bind(('198.18.20.2',18001)); s.listen(); print('ready',flush=True)
while True:
 c,a=s.accept(); c.sendall(a[0].encode()); c.close()
`)
	stdout, err := server.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Process.Kill(); _ = server.Wait() }()
	if !bufio.NewScanner(stdout).Scan() {
		t.Fatal("target server did not start")
	}
	for _, pair := range [][2]string{{"outside", "plant"}, {"edge", "workshop"}, {"wan", "dmz"}} {
		t.Run(pair[0]+"_to_"+pair[1], func(t *testing.T) {
			snap := &rules.Snapshot{Default: rules.ActionDeny, ZoneIfaces: map[string][]string{pair[0]: {"nat0"}, pair[1]: {"nat1"}}, NAT: rules.NATConfig{Enabled: true, EgressZone: pair[0], SourceZones: []string{pair[1]}, PortForwards: []rules.PortForward{{ID: "probe", Enabled: true, IngressZone: pair[0], Proto: "tcp", ListenPort: 18000, DestIP: "198.18.20.2", DestPort: 18001, AllowedSources: []string{"198.18.10.2/32"}}}}}
			apply := func() {
				t.Helper()
				text, err := NewCompiler().CompileFirewall(snap)
				if err != nil {
					t.Fatal(err)
				}
				assertDeclaredSets(t, text)
				if err := NewNftApplier().Apply(ctx, text); err != nil {
					t.Fatal(err)
				}
			}
			probe := func() error {
				out, err := exec.CommandContext(ctx, "ip", "netns", "exec", "natclient", "python3", "-c", `import socket
s=socket.socket(); s.settimeout(1); s.connect(('198.18.10.1',18000)); assert s.recv(64)==b'198.18.20.1'
`).CombinedOutput()
				if err != nil {
					return fmt.Errorf("%w: %s", err, out)
				}
				return nil
			}
			apply()
			if err := probe(); err != nil {
				t.Fatal(err)
			}
			snap.NAT.PortForwards[0].Enabled = false
			apply()
			if err := probe(); err == nil {
				t.Fatal("disabled forward still reachable")
			}
			if listing := command("nft", "list", "ruleset"); strings.Contains(listing, "dnat") {
				t.Fatalf("disabled DNAT survived: %s", listing)
			}
		})
	}
}
