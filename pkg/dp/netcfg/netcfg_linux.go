//go:build linux

package netcfg

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"strings"
	"sync/atomic"
	"unsafe"

	"github.com/containd/containd/pkg/cp/config"
	"golang.org/x/sys/unix"
)

func applyInterfaces(ctx context.Context, ifaces []config.Interface, opts ApplyOptions) error {
	// In appliance mode, we want the kernel to forward traffic between interfaces.
	// Enable per-netns forwarding when there are multiple configured interfaces.
	if shouldEnableForwarding(ifaces) {
		if err := enableForwarding(); err != nil {
			return err
		}
	}

	byName := map[string]config.Interface{}
	for _, iface := range ifaces {
		if strings.TrimSpace(iface.Name) != "" {
			byName[iface.Name] = iface
		}
	}

	resolveDev := func(ref string) string {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			return ""
		}
		if i, ok := byName[ref]; ok {
			if d := strings.TrimSpace(i.Device); d != "" {
				return d
			}
			return strings.TrimSpace(i.Name)
		}
		return ref
	}

	// 1) Ensure bridge/VLAN devices exist and attach members.
	bridgeMembers := map[string]string{} // memberDev -> bridgeDev
	for _, iface := range ifaces {
		t := strings.ToLower(strings.TrimSpace(iface.Type))
		if t == "" || t == "physical" {
			continue
		}
		dev := strings.TrimSpace(iface.Device)
		if dev == "" {
			dev = strings.TrimSpace(iface.Name)
		}
		if dev == "" {
			continue
		}

		switch t {
		case "bridge":
			if err := ensureBridge(dev); err != nil {
				return fmt.Errorf("ensure bridge %s: %w", dev, err)
			}
			if err := setLinkUp(dev); err != nil {
				return fmt.Errorf("set link up %s: %w", dev, err)
			}
			br, err := net.InterfaceByName(dev)
			if err != nil {
				return fmt.Errorf("bridge %s not found after create: %w", dev, err)
			}
			for _, m := range iface.Members {
				memberDev := resolveDev(m)
				if memberDev == "" {
					continue
				}
				bridgeMembers[memberDev] = dev
				if err := setLinkUp(memberDev); err != nil {
					return fmt.Errorf("set link up %s: %w", memberDev, err)
				}
				if err := setLinkMaster(memberDev, br.Index); err != nil {
					return fmt.Errorf("attach %s to bridge %s: %w", memberDev, dev, err)
				}
			}
		case "vlan":
			parentDev := resolveDev(iface.Parent)
			if parentDev == "" {
				return fmt.Errorf("vlan %s missing parent", iface.Name)
			}
			parent, err := net.InterfaceByName(parentDev)
			if err != nil {
				return fmt.Errorf("vlan %s parent %s not found: %w", iface.Name, parentDev, err)
			}
			if err := ensureVLAN(dev, parent.Index, iface.VLANID); err != nil {
				return fmt.Errorf("ensure vlan %s: %w", dev, err)
			}
			if err := setLinkUp(dev); err != nil {
				return fmt.Errorf("set link up %s: %w", dev, err)
			}
		default:
			// validated earlier
		}
	}

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

		// If this kernel device is a bridge member, it should not carry L3 addresses.
		if br := bridgeMembers[dev]; br != "" {
			if len(iface.Addresses) > 0 || strings.TrimSpace(iface.Gateway) != "" {
				return fmt.Errorf("interface %s (%s) is a bridge member of %s; assign addresses to the bridge instead", iface.Name, dev, br)
			}
			continue
		}

		if strings.EqualFold(strings.TrimSpace(iface.AddressMode), "dhcp") {
			// DHCP means "OS-managed addressing". If the interface already has a non-link-local IPv4 address
			// (common in Docker), keep it. Otherwise, attempt a minimal DHCPv4 lease acquisition.
			if err := setLinkUp(dev); err != nil {
				return fmt.Errorf("set link up %s: %w", dev, err)
			}
			nic, err := net.InterfaceByName(dev)
			if err != nil {
				return fmt.Errorf("interface %s (%s) not found: %w", iface.Name, dev, err)
			}
			existing, _ := listAddrs(nic.Index, unix.AF_INET)
			hasIPv4 := false
			for _, ipnet := range existing {
				if ipnet == nil || ipnet.IP == nil {
					continue
				}
				ip4 := ipnet.IP.To4()
				if ip4 == nil {
					continue
				}
				if strings.HasPrefix(ip4.String(), "169.254.") {
					continue
				}
				hasIPv4 = true
				break
			}
			if hasIPv4 {
				continue
			}
			lease, err := dhcpAcquireV4(ctx, dev, 5)
			if err != nil {
				return fmt.Errorf("dhcp on %s: %w", dev, err)
			}
			_, ipnet, err := net.ParseCIDR(strings.TrimSpace(lease.AddrCIDR))
			if err != nil || ipnet == nil {
				return fmt.Errorf("dhcp on %s: invalid lease cidr %q", dev, lease.AddrCIDR)
			}
			if err := addAddr(nic.Index, ipnet); err != nil {
				return fmt.Errorf("dhcp add addr %s %s: %w", dev, ipnet.String(), err)
			}
			if strings.TrimSpace(lease.RouterIP) != "" {
				if err := addDefaultRoute(nic.Index, lease.RouterIP); err != nil {
					return fmt.Errorf("dhcp add default route %s via %s: %w", dev, lease.RouterIP, err)
				}
			}
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
		desiredV4 := map[string]struct{}{}
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
				if ipnet.IP.To4() != nil {
					desiredV4[ipnet.String()] = struct{}{}
				}
				if err := addAddr(nic.Index, ipnet); err != nil {
					return fmt.Errorf("add addr %s %s: %w", dev, ipnet.String(), err)
				}
			}
		}
		// Default behavior for static addressing: ensure the configured IPv4 addresses are the
		// only non-link-local IPv4 addresses on the interface. This makes "set interface ip ..."
		// behave like a real firewall interface assignment, even in containerized deployments.
		replaceV4 := len(desiredV4) > 0
		if opts.Replace || replaceV4 {
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
				if ipnet.IP != nil && ipnet.IP.To4() == nil {
					// Avoid removing link-local IPv6 addresses by default.
					if ipnet.IP.To16() != nil && ipnet.IP.IsLinkLocalUnicast() {
						continue
					}
				}
				// For "static apply" we only replace IPv4; keep any IPv6 global addresses unless
				// the operator explicitly requested a full reconcile.
				if !opts.Replace && replaceV4 && ipnet.IP != nil && ipnet.IP.To4() == nil {
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

func shouldEnableForwarding(ifaces []config.Interface) bool {
	seen := map[string]struct{}{}
	for _, iface := range ifaces {
		if strings.TrimSpace(iface.Zone) == "" {
			continue
		}
		dev := strings.TrimSpace(iface.Device)
		if dev == "" {
			dev = strings.TrimSpace(iface.Name)
		}
		if dev == "" {
			continue
		}
		seen[dev] = struct{}{}
		if len(seen) >= 2 {
			return true
		}
	}
	return false
}

func enableForwarding() error {
	// These sysctls are per-netns on Linux.
	if err := writeSysctl("/proc/sys/net/ipv4/ip_forward", "1"); err != nil {
		// In some containerized environments (notably Docker Desktop / VM-backed runtimes),
		// kernel sysctls may be mounted read-only or blocked. Forwarding is still often
		// effectively enabled in the underlying VM; do not fail interface application
		// just because we can't write the sysctl from inside the container.
		if isSysctlWriteBlocked(err) {
			return nil
		}
		return fmt.Errorf("enable ipv4 forwarding: %w", err)
	}
	// Best-effort: enable v6 forwarding for future dual-stack. Not all kernels expose this.
	_ = writeSysctl("/proc/sys/net/ipv6/conf/all/forwarding", "1")
	return nil
}

func isSysctlWriteBlocked(err error) bool {
	if err == nil {
		return false
	}
	// Common error types include *os.PathError wrapping syscall.Errno.
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == syscall.EPERM || errno == syscall.EACCES || errno == syscall.EROFS
	}
	return os.IsPermission(err)
}

func writeSysctl(path, val string) error {
	val = strings.TrimSpace(val)
	if val == "" {
		return fmt.Errorf("empty sysctl value")
	}
	if !strings.HasSuffix(val, "\n") {
		val += "\n"
	}
	return os.WriteFile(path, []byte(val), 0o644)
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
	msgs, err := syscall.ParseNetlinkMessage(buf[:n])
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
	nic, err := net.InterfaceByName(name)
	if err != nil {
		return err
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
		Type:  unix.RTM_NEWLINK,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK,
		Seq:   seq,
		Pid:   uint32(unix.Getpid()),
	}
	_ = binary.Write(&req, binary.LittleEndian, hdr)
	ifi := unix.IfInfomsg{
		Family: unix.AF_UNSPEC,
		Index:  int32(nic.Index),
		Flags:  unix.IFF_UP,
		Change: unix.IFF_UP,
	}
	_ = binary.Write(&req, binary.LittleEndian, ifi)

	b := req.Bytes()
	(*unix.NlMsghdr)(unsafe.Pointer(&b[0])).Len = uint32(len(b))
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	return readNetlinkAck(fd, seq)
}

const nlaNested = 0x8000

func ensureBridge(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("empty bridge name")
	}
	if _, err := net.InterfaceByName(name); err == nil {
		return nil
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
		Type:  unix.RTM_NEWLINK,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_EXCL,
		Seq:   seq,
		Pid:   uint32(unix.Getpid()),
	}
	_ = binary.Write(&req, binary.LittleEndian, hdr)
	ifi := unix.IfInfomsg{Family: unix.AF_UNSPEC}
	_ = binary.Write(&req, binary.LittleEndian, ifi)

	addRtAttr(&req, unix.IFLA_IFNAME, append([]byte(name), 0))
	addNestedRtAttr(&req, unix.IFLA_LINKINFO, func(b *bytes.Buffer) {
		addRtAttr(b, unix.IFLA_INFO_KIND, append([]byte("bridge"), 0))
	})

	b := req.Bytes()
	(*unix.NlMsghdr)(unsafe.Pointer(&b[0])).Len = uint32(len(b))
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	return readNetlinkAck(fd, seq)
}

func ensureVLAN(name string, parentIndex int, vlanID int) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("empty vlan name")
	}
	if vlanID < 1 || vlanID > 4094 {
		return fmt.Errorf("invalid vlan id %d", vlanID)
	}
	if _, err := net.InterfaceByName(name); err == nil {
		return nil
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
		Type:  unix.RTM_NEWLINK,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_EXCL,
		Seq:   seq,
		Pid:   uint32(unix.Getpid()),
	}
	_ = binary.Write(&req, binary.LittleEndian, hdr)
	ifi := unix.IfInfomsg{Family: unix.AF_UNSPEC}
	_ = binary.Write(&req, binary.LittleEndian, ifi)

	addRtAttr(&req, unix.IFLA_IFNAME, append([]byte(name), 0))
	link := make([]byte, 4)
	binary.LittleEndian.PutUint32(link, uint32(parentIndex))
	addRtAttr(&req, unix.IFLA_LINK, link)

	addNestedRtAttr(&req, unix.IFLA_LINKINFO, func(b *bytes.Buffer) {
		addRtAttr(b, unix.IFLA_INFO_KIND, append([]byte("vlan"), 0))
		addNestedRtAttr(b, unix.IFLA_INFO_DATA, func(d *bytes.Buffer) {
			// IFLA_VLAN_ID is 1 in linux/if_link.h.
			v := make([]byte, 2)
			binary.LittleEndian.PutUint16(v, uint16(vlanID))
			addRtAttr(d, 1 /* IFLA_VLAN_ID */, v)
		})
	})

	b := req.Bytes()
	(*unix.NlMsghdr)(unsafe.Pointer(&b[0])).Len = uint32(len(b))
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	return readNetlinkAck(fd, seq)
}

func setLinkMaster(member string, masterIndex int) error {
	member = strings.TrimSpace(member)
	if member == "" {
		return fmt.Errorf("empty member name")
	}
	nic, err := net.InterfaceByName(member)
	if err != nil {
		return err
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
		Type:  unix.RTM_NEWLINK,
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK,
		Seq:   seq,
		Pid:   uint32(unix.Getpid()),
	}
	_ = binary.Write(&req, binary.LittleEndian, hdr)
	ifi := unix.IfInfomsg{
		Family: unix.AF_UNSPEC,
		Index:  int32(nic.Index),
	}
	_ = binary.Write(&req, binary.LittleEndian, ifi)

	m := make([]byte, 4)
	binary.LittleEndian.PutUint32(m, uint32(masterIndex))
	addRtAttr(&req, unix.IFLA_MASTER, m)

	b := req.Bytes()
	(*unix.NlMsghdr)(unsafe.Pointer(&b[0])).Len = uint32(len(b))
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	return readNetlinkAck(fd, seq)
}

func addNestedRtAttr(parent *bytes.Buffer, attrType uint16, fn func(*bytes.Buffer)) {
	var child bytes.Buffer
	fn(&child)
	addRtAttr(parent, attrType|nlaNested, child.Bytes())
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
	msgs, err := syscall.ParseNetlinkMessage(buf[:n])
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
	msgs, err := syscall.ParseNetlinkMessage(buf[:n])
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
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
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
				var ip net.IP
				for _, a := range parseNetlinkAttrs(m.Data[unix.SizeofIfAddrmsg:]) {
					switch a.Type {
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

type netlinkAttr struct {
	Type  uint16
	Value []byte
}

func parseNetlinkAttrs(b []byte) []netlinkAttr {
	attrs := []netlinkAttr{}
	for len(b) >= 4 {
		l := int(binary.LittleEndian.Uint16(b[0:2]))
		t := binary.LittleEndian.Uint16(b[2:4])
		if l < 4 || l > len(b) {
			break
		}
		val := append([]byte(nil), b[4:l]...)
		attrs = append(attrs, netlinkAttr{Type: t, Value: val})
		// Align to 4.
		adv := (l + 3) &^ 3
		if adv > len(b) {
			break
		}
		b = b[adv:]
	}
	return attrs
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
