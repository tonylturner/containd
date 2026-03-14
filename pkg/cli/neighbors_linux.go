// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

type arpEntry struct {
	ip    string
	mac   string
	iface string
	state string
}

func showNeighbors() Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		entries, err := listARP()
		if err != nil {
			return err
		}
		t := newTable("IP", "MAC", "IFACE", "STATE")
		for _, e := range entries {
			t.addRow(e.ip, e.mac, e.iface, e.state)
		}
		t.render(out)
		return nil
	}
}

func listARP() ([]arpEntry, error) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, fmt.Errorf("read arp: %w", err)
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	first := true
	var out []arpEntry
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		// Header:
		// IP address  HW type  Flags  HW address  Mask  Device
		if first {
			first = false
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		ip := fields[0]
		flags := strings.ToLower(fields[2])
		mac := fields[3]
		iface := fields[5]

		// Typical flags: 0x0 (incomplete), 0x2 (complete)
		var state string
		switch flags {
		case "0x0":
			state = "incomplete"
		case "0x2":
			state = "reachable"
		default:
			state = flags
		}
		out = append(out, arpEntry{ip: ip, mac: mac, iface: iface, state: state})
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("read arp: %w", err)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].iface != out[j].iface {
			return out[i].iface < out[j].iface
		}
		return out[i].ip < out[j].ip
	})
	return out, nil
}
