// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Link holds one kernel link's four cumulative traffic counters.
type Link struct {
	Epoch                                  string
	RxBytes, TxBytes, RxPackets, TxPackets uint64
}

// ReadLink reads Linux's virtual kernel files, not process capture counters.
func ReadLink(device string) (Link, error) { return readLink("/", device) }

func readLink(root, device string) (Link, error) {
	var l Link
	if device == "" || device == "." || device == ".." || strings.ContainsAny(device, "/\\") {
		return l, fmt.Errorf("invalid device %q", device)
	}
	boot, err := os.ReadFile(filepath.Join(root, "proc/sys/kernel/random/boot_id"))
	if err != nil {
		return l, err
	}
	ns, err := os.Readlink(filepath.Join(root, "proc/self/ns/net"))
	if err != nil {
		return l, err
	}
	path := filepath.Join(root, "sys/class/net", device)
	index, err := os.ReadFile(filepath.Join(path, "ifindex"))
	if err != nil {
		return l, err
	}
	l.Epoch = strings.TrimSpace(string(boot)) + ":" + ns + ":" + strings.TrimSpace(string(index))
	for _, c := range []struct {
		name string
		dst  *uint64
	}{{"rx_bytes", &l.RxBytes}, {"tx_bytes", &l.TxBytes}, {"rx_packets", &l.RxPackets}, {"tx_packets", &l.TxPackets}} {
		text, err := os.ReadFile(filepath.Join(path, "statistics", c.name))
		if err != nil {
			return Link{}, err
		}
		*c.dst, err = strconv.ParseUint(strings.TrimSpace(string(text)), 10, 64)
		if err != nil {
			return Link{}, err
		}
	}
	return l, nil
}
