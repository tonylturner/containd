//go:build linux

package netcfg

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"unsafe"

	"github.com/containd/containd/pkg/cp/config"
	"golang.org/x/sys/unix"
)

func applyInterfaces(ctx context.Context, ifaces []config.Interface) error {
	for _, iface := range ifaces {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		dev := strings.TrimSpace(iface.Device)
		if dev == "" {
			dev = strings.TrimSpace(iface.Name)
		}
		if dev == "" {
			continue
		}
		// Safety: only apply when config explicitly provides addresses.
		// We avoid deleting or overriding existing addresses in early phases.
		if len(iface.Addresses) == 0 {
			continue
		}
		nic, err := net.InterfaceByName(dev)
		if err != nil {
			return fmt.Errorf("interface %s (%s) not found: %w", iface.Name, dev, err)
		}
		if err := setLinkUp(dev); err != nil {
			return fmt.Errorf("set link up %s: %w", dev, err)
		}
		for _, cidr := range iface.Addresses {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			cidr = strings.TrimSpace(cidr)
			if cidr == "" {
				continue
			}
			if _, ipnet, err := net.ParseCIDR(cidr); err != nil || ipnet == nil || ipnet.IP == nil {
				return fmt.Errorf("interface %s invalid CIDR %q", iface.Name, cidr)
			} else {
				if err := addAddr(nic.Index, ipnet); err != nil {
					return fmt.Errorf("add addr %s %s: %w", dev, ipnet.String(), err)
				}
			}
		}
	}
	return nil
}

func setLinkUp(name string) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	var ifr unix.Ifreq
	copy(ifr.Name[:], name)
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, &ifr); err != nil {
		return err
	}
	flags := ifr.Uint16()
	flags |= unix.IFF_UP
	ifr.SetUint16(flags)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, &ifr); err != nil {
		return err
	}
	return nil
}

var nlSeq uint32

func addAddr(ifIndex int, ipnet *net.IPNet) error {
	if ipnet == nil {
		return nil
	}
	family := unix.AF_INET
	ip := ipnet.IP
	if ip == nil {
		return nil
	}
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
		family = unix.AF_INET
	} else {
		ip = ip.To16()
		family = unix.AF_INET6
		if ip == nil {
			return errors.New("invalid IP")
		}
	}
	prefixLen, _ := ipnet.Mask.Size()

	// Netlink route socket.
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}

	seq := atomic.AddUint32(&nlSeq, 1)

	// Build message.
	var req bytes.Buffer
	hdr := unix.NlMsghdr{
		Type:  unix.RTM_NEWADDR,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_EXCL,
		Seq:   seq,
		Pid:   uint32(unix.Getpid()),
	}
	// Placeholder for Len; set after writing.
	_ = binary.Write(&req, binary.LittleEndian, hdr)

	ifa := unix.IfAddrmsg{
		Family:    uint8(family),
		Prefixlen: uint8(prefixLen),
		Flags:     0,
		Scope:     0,
		Index:     uint32(ifIndex),
	}
	_ = binary.Write(&req, binary.LittleEndian, ifa)

	// IFA_LOCAL + IFA_ADDRESS
	addRtAttr(&req, unix.IFA_LOCAL, ip)
	addRtAttr(&req, unix.IFA_ADDRESS, ip)

	// Patch header length.
	b := req.Bytes()
	(*unix.NlMsghdr)(unsafe.Pointer(&b[0])).Len = uint32(len(b))

	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}

	// Read ACK.
	buf := make([]byte, 8192)
	n, _, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {
		return err
	}
	msgs, err := unix.ParseNetlinkMessage(buf[:n])
	if err != nil {
		return err
	}
	for _, m := range msgs {
		if m.Header.Seq != seq {
			continue
		}
		switch m.Header.Type {
		case unix.NLMSG_ERROR:
			if len(m.Data) < 4 {
				return errors.New("netlink error")
			}
			code := int32(binary.LittleEndian.Uint32(m.Data[:4]))
			if code == 0 {
				return nil
			}
			// EEXIST when already present.
			if -code == int32(unix.EEXIST) {
				return nil
			}
			return unix.Errno(-code)
		case unix.NLMSG_DONE:
			return nil
		}
	}
	return nil
}

func addRtAttr(b *bytes.Buffer, attrType uint16, data []byte) {
	// rtattr header is (len,type) uint16 each.
	const hdrLen = 4
	l := hdrLen + len(data)
	aligned := (l + 3) & ^3
	h := unix.RtAttr{Len: uint16(l), Type: attrType}
	_ = binary.Write(b, binary.LittleEndian, h)
	_, _ = b.Write(data)
	// Pad to 4 bytes.
	for i := l; i < aligned; i++ {
		_ = b.WriteByte(0)
	}
}

