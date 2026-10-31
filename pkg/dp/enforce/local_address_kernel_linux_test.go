// SPDX-License-Identifier: Apache-2.0
//go:build linux

package enforce

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Both local addresses stay assigned throughout: only the device address-set
// elements change. New and established TCP connections must follow the current
// set in the DNAT lookup and original-destination admission predicate.
func TestKernelSpikeS5DNATOriginalDestinationSetUpdates(t *testing.T) {
	t.Run("new-connections", testNewDNATAddressSetConnections)
	t.Run("established-rematch", testEstablishedDNATAddressSetRematch)
}

func testNewDNATAddressSetConnections(t *testing.T) {
	lab := newNetnsLab(t, "local", 41, 30*time.Second)
	lab.run(t, "ip", "addr", "add", "198.18.41.3/24", "dev", "local0")
	lab.run(t, "ip", "-n", lab.client, "route", "add", "default", "via", "198.18.41.1")
	lab.run(t, "ip", "-n", lab.target, "route", "add", "default", "via", "198.18.51.1")
	lab.serveTarget(t, "198.18.51.2", 18001)
	lab.nft(t, `table inet spike_local {
 set local4_local0 { type ipv4_addr; elements = { 198.18.41.1 }; }
 counter translated { }
 counter admitted { }
 chain pre { type nat hook prerouting priority dstnat; policy accept;
 iifname "local0" ip daddr @local4_local0 tcp dport 18000 counter name translated dnat ip to 198.18.51.2:18001
 }
 chain admission { type filter hook forward priority 0; policy drop;
 ct state established accept
 iifname "local0" ip daddr 198.18.51.2 tcp dport 18001 ct original ip daddr @local4_local0 counter name admitted accept
 }
}`)
	t.Cleanup(func() { lab.nft(t, "delete table inet spike_local") })
	if err := lab.probe("198.18.41.1", 18000, "198.18.41.2"); err != nil {
		t.Fatalf("initial local address: %v", err)
	}
	for _, addr := range []string{"198.18.41.3", "198.18.51.1"} {
		if err := lab.probe(addr, 18000, "198.18.41.2"); err == nil {
			t.Fatalf("nonmember local address %s unexpectedly translated", addr)
		}
	}
	// Only set-element operations: no replacement of a chain, hook or table.
	lab.nft(t, `delete element inet spike_local local4_local0 { 198.18.41.1 }
add element inet spike_local local4_local0 { 198.18.41.3 }`)
	if err := lab.probe("198.18.41.3", 18000, "198.18.41.2"); err != nil {
		t.Fatalf("new local address after element update: %v", err)
	}
	if err := lab.probe("198.18.41.1", 18000, "198.18.41.2"); err == nil {
		t.Fatal("removed local address still translated new connections")
	}
	// The original destination is not the translated backend; direct routing
	// to that same backend cannot inherit the forward's permission.
	if err := lab.probe("198.18.51.2", 18001, "198.18.41.2"); err == nil {
		t.Fatal("direct backend connection inherited the DNAT permission")
	}
	for _, name := range []string{"translated", "admitted"} {
		out := lab.run(t, "nft", "list", "counter", "inet", "spike_local", name)
		if !strings.Contains(out, "packets 2 ") {
			t.Fatalf("%s expected two successful new connections: %s", name, out)
		}
		t.Log(out)
	}
}

func testEstablishedDNATAddressSetRematch(t *testing.T) {
	lab := newNetnsLab(t, "rematch", 42, 30*time.Second)
	lab.run(t, "ip", "-n", lab.target, "route", "add", "default", "via", "198.18.52.1")
	lab.nft(t, `table inet spike_rematch {
 set local4_rematch0 { type ipv4_addr; elements = { 198.18.42.1 }; }
 counter matched { }
 counter missed { }
 chain pre { type nat hook prerouting priority dstnat; policy accept;
 iifname "rematch0" ip daddr @local4_rematch0 tcp dport 18000 ct mark set 1 dnat ip to 198.18.52.2:18001
 }
 chain admission { type filter hook forward priority 0; policy drop;
 ct mark & 1 == 1 ct state established ct original ip daddr @local4_rematch0 counter name matched accept
 iifname "rematch0" ct mark & 1 == 1 ct state new accept
 ct mark & 1 == 1 ct state established counter name missed drop
 }
}`)
	t.Cleanup(func() { lab.nft(t, "delete table inet spike_rematch") })
	_, server := startAddressSetPeer(t, lab, lab.target, `import socket
s=socket.socket(); s.bind(("198.18.52.2",18001)); s.listen(); print("ready")
c,_=s.accept()
c.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
while True:
 b=c.recv(64)
 if not b: break
 c.sendall(b)
`)
	addressSetPeerLine(t, server, "ready")
	input, client := startAddressSetPeer(t, lab, lab.client, `import socket,sys
s=socket.socket(); s.settimeout(4)
s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
s.connect(("198.18.42.1",18000))
s.sendall(b"A"); assert s.recv(1)==b"A"; print("established")
assert sys.stdin.readline().strip()=="remove"
s.sendall(b"B"); s.settimeout(0.3)
try:
 b=s.recv(1)
 raise AssertionError("removed address delivered data: "+repr(b))
except socket.timeout:
 print("blocked")
assert sys.stdin.readline().strip()=="restore"
s.settimeout(4)
assert s.recv(1)==b"B"
s.sendall(b"C"); assert s.recv(1)==b"C"
print("restored")
sys.stdin.readline()
`)
	addressSetPeerLine(t, client, "established")
	initial := addressSetCounters(t, lab)
	if initial["matched"] == 0 || initial["missed"] != 0 {
		t.Fatalf("initial established counters: %v", initial)
	}
	// Keep the IP address, socket and conntrack/NAT binding intact. Neither
	// update reloads a table, changes a rule, nor deletes a conntrack entry.
	lab.nft(t, "delete element inet spike_rematch local4_rematch0 { 198.18.42.1 }")
	before := addressSetCounters(t, lab)
	if _, err := fmt.Fprintln(input, "remove"); err != nil {
		t.Fatal(err)
	}
	addressSetPeerLine(t, client, "blocked")
	removed := addressSetCounters(t, lab)
	if removed["matched"] != before["matched"] || removed["missed"] <= before["missed"] {
		t.Fatalf("removed address must miss on the next established packet: before=%v after=%v", before, removed)
	}
	lab.nft(t, "add element inet spike_rematch local4_rematch0 { 198.18.42.1 }")
	if _, err := fmt.Fprintln(input, "restore"); err != nil {
		t.Fatal(err)
	}
	addressSetPeerLine(t, client, "restored")
	restored := addressSetCounters(t, lab)
	if restored["matched"] <= removed["matched"] {
		t.Fatalf("restored address did not match the existing flow: removed=%v restored=%v", removed, restored)
	}
	t.Logf("same established TCP socket: initial=%v deleted=%v restored=%v", initial, removed, restored)
}

func startAddressSetPeer(t *testing.T, lab *netnsLab, ns, script string) (io.WriteCloser, *bufio.Scanner) {
	t.Helper()
	cmd := exec.CommandContext(lab.ctx, "ip", "netns", "exec", ns, "python3", "-u", "-c", script)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = input.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if stderr.Len() != 0 {
			t.Errorf("address-set peer: %s", stderr.String())
		}
	})
	return input, bufio.NewScanner(output)
}

func addressSetPeerLine(t *testing.T, output *bufio.Scanner, want string) {
	t.Helper()
	if !output.Scan() || output.Text() != want {
		t.Fatalf("address-set peer: got %q, want %q: %v", output.Text(), want, output.Err())
	}
}

func addressSetCounters(t *testing.T, lab *netnsLab) map[string]uint64 {
	t.Helper()
	var doc struct {
		Nftables []struct {
			Counter *struct {
				Name    string
				Packets uint64
			} `json:"counter"`
		} `json:"nftables"`
	}
	out := lab.run(t, "nft", "-j", "list", "table", "inet", "spike_rematch")
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	counts := map[string]uint64{}
	for _, item := range doc.Nftables {
		if c := item.Counter; c != nil {
			counts[c.Name] = c.Packets
		}
	}
	if len(counts) != 2 {
		t.Fatalf("missing established-flow counters: %v", counts)
	}
	return counts
}
