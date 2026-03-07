// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cli

import (
	"context"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
)

func osInterfaceAddrs(name string) ([]string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, nil
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		s := strings.TrimSpace(a.String())
		if s != "" {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out, nil
}

func showInterfacesOS() Command {
	return func(ctx context.Context, out io.Writer, args []string) error {
		if out == nil {
			return nil
		}
		if len(args) != 0 {
			return fmt.Errorf("usage: show interfaces os")
		}
		ifaces, err := net.Interfaces()
		if err != nil {
			return err
		}
		if len(ifaces) == 0 {
			fmt.Fprintln(out, "No OS interfaces.")
			return nil
		}
		sort.Slice(ifaces, func(i, j int) bool { return ifaces[i].Index < ifaces[j].Index })

		t := newTable("IFACE", "INDEX", "STATE", "FLAGS", "MAC", "MTU", "ADDRS")
		for _, iface := range ifaces {
			state := "down"
			if (iface.Flags & net.FlagUp) != 0 {
				state = "up"
			}

			flags := []string{}
			for _, f := range []struct {
				flag net.Flags
				name string
			}{
				{net.FlagBroadcast, "BCAST"},
				{net.FlagLoopback, "LOOP"},
				{net.FlagPointToPoint, "P2P"},
				{net.FlagMulticast, "MCAST"},
			} {
				if (iface.Flags & f.flag) != 0 {
					flags = append(flags, f.name)
				}
			}
			flagStr := "—"
			if len(flags) > 0 {
				flagStr = strings.Join(flags, "|")
			}

			mac := "—"
			if hw := strings.TrimSpace(iface.HardwareAddr.String()); hw != "" {
				mac = hw
			}
			mtu := "—"
			if iface.MTU > 0 {
				mtu = strconv.Itoa(iface.MTU)
			}

			addrStr := "—"
			if addrs, err := iface.Addrs(); err == nil && len(addrs) > 0 {
				ss := make([]string, 0, len(addrs))
				for _, a := range addrs {
					s := strings.TrimSpace(a.String())
					if s != "" {
						ss = append(ss, s)
					}
				}
				if len(ss) > 0 {
					addrStr = strings.Join(ss, ", ")
				}
			}

			t.addRow(
				iface.Name,
				strconv.Itoa(iface.Index),
				state,
				flagStr,
				mac,
				mtu,
				truncate(addrStr, 72),
			)
		}
		t.render(out)
		return nil
	}
}
