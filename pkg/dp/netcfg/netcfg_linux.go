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

func applyInterfaces(ctx context.Context, ifaces []config.Interface, opts ApplyOptions) error {
	for _, iface := range ifaces {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if strings.EqualFold(strings.TrimSpace(iface.AddressMode), "dhcp") {
			// DHCP is a placeholder for now; leave any existing OS config untouched.
			continue
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
		desired := map[string]struct{}{}
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
				desired[ipnet.String()] = struct{}{}
				if err := addAddr(nic.Index, ipnet); err != nil {
					return fmt.Errorf("add addr %s %s: %w", dev, ipnet.String(), err)
				}
			}
		}
		if opts.Replace {
			existing, err := listAddrs(nic.Index, unix.AF_UNSPEC)
			if err != nil {
				return fmt.Errorf("list addrs %s: %w", dev, err)
			}
			for _, ipnet := range existing {
				if ipnet == nil {
					continue
				}
				if _, ok := desired[ipnet.String()]; ok {
					continue
				}
				// Avoid removing link-local IPv6 addresses by default.
				if ipnet.IP != nil && ipnet.IP.To16() != nil && ipnet.IP.To4() == nil && ipnet.IP.IsLinkLocalUnicast() {
					continue
				}
				if err := delAddr(nic.Index, ipnet); err != nil {
					return fmt.Errorf("del addr %s %s: %w", dev, ipnet.String(), err)
				}
			}
		}
		if gw := strings.TrimSpace(iface.Gateway); gw != "" {
			if err := addDefaultRoute(nic.Index, gw); err != nil {
				return fmt.Errorf("add default route %s via %s: %w", dev, gw, err)
			}
		}
	}
	return nil
}

func addDefaultRoute(ifIndex int, gateway string) error {
	ip := net.ParseIP(strings.TrimSpace(gateway))
	if ip == nil {
		return fmt.Errorf("invalid gateway %q", gateway)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("only IPv4 gateways supported for now: %q", gateway)
	}

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}

	seq := atomic.AddUint32(&nlSeq, 1)
	var req bytes.Buffer
	hdr := unix.NlMsghdr{
		Type:  unix.RTM_NEWROUTE,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_REPLACE,
		Seq:   seq,
		Pid:   uint32(unix.Getpid()),
	}
	_ = binary.Write(&req, binary.LittleEndian, hdr)
	rtm := unix.RtMsg{
		Family:   unix.AF_INET,
		Dst_len:  0,
		Src_len:  0,
		Tos:      0,
		Table:    unix.RT_TABLE_MAIN,
		Protocol: unix.RTPROT_STATIC,
		Scope:    unix.RT_SCOPE_UNIVERSE,
		Type:     unix.RTN_UNICAST,
		Flags:    0,
	}
	_ = binary.Write(&req, binary.LittleEndian, rtm)

	oif := make([]byte, 4)
	binary.LittleEndian.PutUint32(oif, uint32(ifIndex))
	addRtAttr(&req, unix.RTA_OIF, oif)
	addRtAttr(&req, unix.RTA_GATEWAY, ip4)

	b := req.Bytes()
	(*unix.NlMsghdr)(unsafe.Pointer(&b[0])).Len = uint32(len(b))
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}

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
		if m.Header.Type != unix.NLMSG_ERROR {
			continue
		}
		if len(m.Data) < 4 {
			return errors.New("netlink error")
		}
		code := int32(binary.LittleEndian.Uint32(m.Data[:4]))
		if code == 0 {
			return nil
		}
		if -code == int32(unix.EEXIST) {
			return nil
		}
		return unix.Errno(-code)
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

func delAddr(ifIndex int, ipnet *net.IPNet) error {
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

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	seq := atomic.AddUint32(&nlSeq, 1)

	var req bytes.Buffer
	hdr := unix.NlMsghdr{
		Type:  unix.RTM_DELADDR,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK,
		Seq:   seq,
		Pid:   uint32(unix.Getpid()),
	}
	_ = binary.Write(&req, binary.LittleEndian, hdr)
	ifa := unix.IfAddrmsg{
		Family:    uint8(family),
		Prefixlen: uint8(prefixLen),
		Flags:     0,
		Scope:     0,
		Index:     uint32(ifIndex),
	}
	_ = binary.Write(&req, binary.LittleEndian, ifa)
	addRtAttr(&req, unix.IFA_LOCAL, ip)
	addRtAttr(&req, unix.IFA_ADDRESS, ip)

	b := req.Bytes()
	(*unix.NlMsghdr)(unsafe.Pointer(&b[0])).Len = uint32(len(b))
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
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
		if m.Header.Type != unix.NLMSG_ERROR {
			continue
		}
		if len(m.Data) < 4 {
			return errors.New("netlink error")
		}
		code := int32(binary.LittleEndian.Uint32(m.Data[:4]))
		if code == 0 {
			return nil
		}
		if -code == int32(unix.EADDRNOTAVAIL) {
			return nil
		}
		return unix.Errno(-code)
	}
	return nil
}

func listAddrs(ifIndex int, family int) ([]*net.IPNet, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}

	seq := atomic.AddUint32(&nlSeq, 1)
	var req bytes.Buffer
	hdr := unix.NlMsghdr{
		Type:  unix.RTM_GETADDR,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_DUMP,
		Seq:   seq,
		Pid:   uint32(unix.Getpid()),
	}
	_ = binary.Write(&req, binary.LittleEndian, hdr)
	ifa := unix.IfAddrmsg{Family: uint8(family)}
	_ = binary.Write(&req, binary.LittleEndian, ifa)
	b := req.Bytes()
	(*unix.NlMsghdr)(unsafe.Pointer(&b[0])).Len = uint32(len(b))
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}

	out := []*net.IPNet{}
	buf := make([]byte, 1<<16)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return nil, err
		}
		msgs, err := unix.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return nil, err
		}
		for _, m := range msgs {
			if m.Header.Seq != seq {
				continue
			}
			switch m.Header.Type {
			case unix.NLMSG_DONE:
				return out, nil
			case unix.NLMSG_ERROR:
				if len(m.Data) < 4 {
					return nil, errors.New("netlink error")
				}
				code := int32(binary.LittleEndian.Uint32(m.Data[:4]))
				if code == 0 {
					continue
				}
				return nil, unix.Errno(-code)
			case unix.RTM_NEWADDR:
				if len(m.Data) < unix.SizeofIfAddrmsg {
					continue
				}
				am := (*unix.IfAddrmsg)(unsafe.Pointer(&m.Data[0]))
				if int(am.Index) != ifIndex {
					continue
				}
				attrs, err := unix.ParseNetlinkRouteAttr(m.Data[unix.SizeofIfAddrmsg:])
				if err != nil {
					continue
				}
				var ip net.IP
				for _, a := range attrs {
					switch a.Attr.Type {
					case unix.IFA_LOCAL:
						ip = net.IP(append([]byte(nil), a.Value...))
					case unix.IFA_ADDRESS:
						if ip == nil {
							ip = net.IP(append([]byte(nil), a.Value...))
						}
					}
				}
				if ip == nil {
					continue
				}
				ones := int(am.Prefixlen)
				var bits int
				if am.Family == unix.AF_INET {
					ip = ip.To4()
					bits = 32
				} else {
					ip = ip.To16()
					bits = 128
				}
				if ip == nil {
					continue
				}
				out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(ones, bits)})
			}
		}
	}
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
