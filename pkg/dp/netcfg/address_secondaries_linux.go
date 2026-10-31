// SPDX-License-Identifier: Apache-2.0
//go:build linux

package netcfg

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Linux otherwise deletes every same-subnet secondary when deleting a primary.
// Promotion exists since 2.6.12; its rtnetlink per-device configuration API is
// already present in 2.6.39. Write only through netlink (NET_ADMIN), since Docker mounts
// /proc/sys read-only. Restore the original setting; never change all/default.
func preserveIPv4Secondaries(dev string) (func() error, error) {
	path := filepath.Join("/proc/sys/net/ipv4/conf", dev, "promote_secondaries")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	old, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 32)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if old != 0 {
		return func() error { return nil }, nil
	}
	nic, err := net.InterfaceByName(dev)
	if err != nil {
		return nil, err
	}
	if err := setIPv4SecondaryPromotion(nic.Index, 1); err != nil {
		return nil, fmt.Errorf("enable secondary promotion %s: %w", dev, err)
	}
	return func() error {
		if err := setIPv4SecondaryPromotion(nic.Index, uint32(old)); err != nil {
			return fmt.Errorf("restore secondary promotion %s: %w", dev, err)
		}
		return nil
	}, nil
}

func setIPv4SecondaryPromotion(index int, value uint32) error {
	// linux/ip.h: IPV4_DEVCONF_PROMOTE_SECONDARIES (stable UAPI enum).
	const promoteSecondaries = 20
	var conf, inet, af, payload bytes.Buffer
	netlinkAttrU32(&conf, promoteSecondaries, value)
	addRtAttr(&inet, unix.IFLA_INET_CONF|unix.NLA_F_NESTED, conf.Bytes())
	addRtAttr(&af, unix.AF_INET|unix.NLA_F_NESTED, inet.Bytes())
	payload.Write(netlinkPayload(unix.IfInfomsg{Family: unix.AF_UNSPEC, Index: int32(index)}))
	addRtAttr(&payload, unix.IFLA_AF_SPEC|unix.NLA_F_NESTED, af.Bytes())
	_, err := netlinkRequest(context.Background(), unix.RTM_NEWLINK, unix.NLM_F_ACK, payload.Bytes())
	return err
}
