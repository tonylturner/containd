// SPDX-License-Identifier: Apache-2.0
//go:build linux

package enforce

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// netnsLab routes between a client and a target network namespace through
// this namespace's forward chain. Tests using it replace containd's nft
// tables and enable forwarding in this namespace, so they run only when CONTAIND_NETNS_KERNEL_TEST=1 inside a disposable
// privileged Linux container with nft, iproute2 and Python, for example:
//
//	GOOS=linux CGO_ENABLED=0 go test -c -o build/enforce.test ./pkg/dp/enforce
//	docker run --rm --privileged -e CONTAIND_NETNS_KERNEL_TEST=1 -v "$PWD/build:/w" alpine:3.21 \
//	  sh -c 'apk add -q nftables iproute2 python3 && /w/enforce.test -test.run Kernel -test.v'
type netnsLab struct {
	ctx    context.Context
	client string // namespace behind <name>0, 198.18.<subnet>.2
	target string // namespace behind <name>1, 198.18.<subnet+10>.2
}

// newNetnsLab creates the namespaces and veth pairs <name>0 and <name>1
// with host addresses 198.18.<subnet>.1/24 and 198.18.<subnet+10>.1/24,
// and enables forwarding. The target gets no default route. Every command
// of the lab, cleanup included, shares one timeout.
func newNetnsLab(t *testing.T, name string, subnet int, timeout time.Duration) *netnsLab {
	t.Helper()
	if os.Getenv("CONTAIND_NETNS_KERNEL_TEST") != "1" || os.Geteuid() != 0 {
		t.Skip("requires CONTAIND_NETNS_KERNEL_TEST=1 in a disposable privileged Linux container with nft, iproute2 and Python")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	t.Cleanup(cancel) // registered first, so it runs after every other cleanup
	lab := &netnsLab{ctx: ctx, client: name + "client", target: name + "target"}
	for i, ns := range []string{lab.client, lab.target} {
		dev, peer := fmt.Sprintf("%s%d", name, i), fmt.Sprintf("%sp%d", name, i)
		lab.run(t, "ip", "netns", "add", ns)
		t.Cleanup(func() { lab.run(t, "ip", "netns", "del", ns) })
		lab.run(t, "ip", "link", "add", dev, "type", "veth", "peer", "name", peer)
		t.Cleanup(func() { lab.run(t, "ip", "link", "del", dev) })
		lab.run(t, "ip", "link", "set", peer, "netns", ns)
		lab.run(t, "ip", "addr", "add", fmt.Sprintf("198.18.%d.1/24", subnet+i*10), "dev", dev)
		lab.run(t, "ip", "link", "set", dev, "up")
		lab.run(t, "ip", "-n", ns, "addr", "add", fmt.Sprintf("198.18.%d.2/24", subnet+i*10), "dev", peer)
		lab.run(t, "ip", "-n", ns, "link", "set", peer, "up")
		lab.run(t, "ip", "-n", ns, "link", "set", "lo", "up")
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0600); err != nil {
		t.Fatal(err)
	}
	return lab
}

// run runs a command in this namespace; t is the calling (sub)test.
func (l *netnsLab) run(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.CommandContext(l.ctx, args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %v: %s", args, err, out)
	}
	return string(out)
}

// apply compiles snap with c and installs it in this namespace. The tables
// c owns are removed when the calling (sub)test ends.
func (l *netnsLab) apply(t *testing.T, c *Compiler, snap *rules.Snapshot) {
	t.Helper()
	text, err := c.CompileFirewall(snap)
	if err != nil {
		t.Fatal(err)
	}
	assertDeclaredSets(t, text)
	l.nft(t, text)
	t.Cleanup(func() { l.nft(t, c.DeleteTables()) })
}

// nft applies an nft script in this namespace.
func (l *netnsLab) nft(t *testing.T, script string) {
	t.Helper()
	if err := NewNftApplier().Apply(l.ctx, script); err != nil {
		t.Fatal(err)
	}
}

// serveTarget runs a TCP server in the target namespace on addr:port that
// sends each client its source address and closes. It lives until the
// test that started it ends.
func (l *netnsLab) serveTarget(t *testing.T, addr string, port int) {
	t.Helper()
	server := exec.CommandContext(l.ctx, "ip", "netns", "exec", l.target, "python3", "-u", "-c", fmt.Sprintf(`import socket
s=socket.socket(); s.bind((%q,%d)); s.listen(); print('ready',flush=True)
while True:
 c,a=s.accept(); c.sendall(a[0].encode()); c.close()
`, addr, port))
	stdout, err := server.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })
	if !bufio.NewScanner(stdout).Scan() {
		t.Fatal("target server did not start")
	}
}

// probe connects from the client namespace to addr:port and requires the
// server to report source address seen.
func (l *netnsLab) probe(addr string, port int, seen string) error {
	out, err := exec.CommandContext(l.ctx, "ip", "netns", "exec", l.client, "python3", "-c", fmt.Sprintf(`import socket
s=socket.socket(); s.settimeout(1); s.connect((%q,%d)); assert s.recv(64)==%q.encode()
`, addr, port, seen)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}
