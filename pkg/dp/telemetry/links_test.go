// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLinkEpochAndFailures(t *testing.T) {
	root := t.TempDir()
	write := func(path, value string) {
		t.Helper()
		path = filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("proc/sys/kernel/random/boot_id", "boot\n")
	if err := os.MkdirAll(filepath.Join(root, "proc/self/ns"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("net:[42]", filepath.Join(root, "proc/self/ns/net")); err != nil {
		t.Fatal(err)
	}
	write("sys/class/net/eth0/ifindex", "7\n")
	for _, name := range []string{"rx_bytes", "tx_bytes", "rx_packets", "tx_packets"} {
		write("sys/class/net/eth0/statistics/"+name, "0\n")
	}
	a, err := readLink(root, "eth0")
	if err != nil {
		t.Fatal(err)
	}
	if a.Epoch != "boot:net:[42]:7" || a.RxBytes != 0 {
		t.Fatal(a)
	}
	write("sys/class/net/eth0/ifindex", "8")
	b, err := readLink(root, "eth0")
	if err != nil || b.Epoch == a.Epoch {
		t.Fatalf("%+v %v", b, err)
	}
	write("sys/class/net/eth0/statistics/rx_bytes", "broken")
	if _, err := readLink(root, "eth0"); err == nil {
		t.Fatal("parse error hidden")
	}
	for _, d := range []string{"missing", "../eth0"} {
		if _, err := readLink(root, d); err == nil {
			t.Fatalf("read %q succeeded", d)
		}
	}
}
