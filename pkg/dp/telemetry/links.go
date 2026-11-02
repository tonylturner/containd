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

// linkReadError marks a failure after the interface's ifindex confirmed that
// the device exists. Such failures remain unavailable even when the missing
// file itself wraps fs.ErrNotExist.
type linkReadError struct {
	err error
}

func (e *linkReadError) Error() string { return e.err.Error() }
func (e *linkReadError) Unwrap() error { return e.err }

// ReadLink reads Linux's virtual kernel files, not process capture counters.
func ReadLink(device string) (Link, error) { return readLink("/", device) }

func readLink(root, device string) (Link, error) {
	var l Link
	if device == "" || device == "." || device == ".." || strings.ContainsAny(device, "/\\") {
		return l, fmt.Errorf("invalid device %q", device)
	}
	path := filepath.Join(root, "sys/class/net", device)
	index, err := os.ReadFile(filepath.Join(path, "ifindex"))
	if err != nil {
		return l, err
	}
	readExisting := func(path string) ([]byte, error) {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, &linkReadError{err: err}
		}
		return data, nil
	}
	boot, err := readExisting(filepath.Join(root, "proc/sys/kernel/random/boot_id"))
	if err != nil {
		return l, err
	}
	ns, err := os.Readlink(filepath.Join(root, "proc/self/ns/net"))
	if err != nil {
		return l, &linkReadError{err: err}
	}
	l.Epoch = strings.TrimSpace(string(boot)) + ":" + ns + ":" + strings.TrimSpace(string(index))
	for _, c := range []struct {
		name string
		dst  *uint64
	}{{"rx_bytes", &l.RxBytes}, {"tx_bytes", &l.TxBytes}, {"rx_packets", &l.RxPackets}, {"tx_packets", &l.TxPackets}} {
		text, err := readExisting(filepath.Join(path, "statistics", c.name))
		if err != nil {
			return Link{}, err
		}
		*c.dst, err = strconv.ParseUint(strings.TrimSpace(string(text)), 10, 64)
		if err != nil {
			return Link{}, &linkReadError{err: err}
		}
	}
	return l, nil
}
