//go:build linux

package dhcpd

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/containd/containd/pkg/cp/config"
	"golang.org/x/sys/unix"
)

const (
	dhcpClientPort = 68
	dhcpServerPort = 67

	dhcpListenPort = 1067 // unprivileged; nft redirects UDP/67 -> 1067

	dhcpOpRequest = 1
	dhcpOpReply   = 2

	dhcpHtypeEthernet = 1
	dhcpHlenEthernet  = 6

	dhcpMsgDiscover = 1
	dhcpMsgOffer    = 2
	dhcpMsgRequest  = 3
	dhcpMsgDecline  = 4
	dhcpMsgAck      = 5
	dhcpMsgNak      = 6

	dhcpOptSubnetMask    = 1
	dhcpOptRouter        = 3
	dhcpOptDNSServer     = 6
	dhcpOptHostName      = 12
	dhcpOptDomainName    = 15
	dhcpOptRequestIP     = 50
	dhcpOptLeaseTime     = 51
	dhcpOptMsgType       = 53
	dhcpOptServerID      = 54
	dhcpOptParamReqList  = 55
	dhcpOptClientID      = 61
	dhcpOptEnd           = 255
	dhcpOptPad           = 0
	dhcpMagicCookie uint32 = 0x63825363
)

type request struct {
	xid       uint32
	flags     uint16
	mac       string
	msgType   byte
	reqIP     net.IP
	hostname  string
	clientID  []byte
}

func serveDHCPv4(ctx context.Context, dev string, cfg config.DHCPConfig, pl pool, m *Manager) error {
	dev = strings.TrimSpace(dev)
	if dev == "" {
		return fmt.Errorf("dhcp: empty device")
	}

	iface, err := net.InterfaceByName(dev)
	if err != nil {
		return fmt.Errorf("dhcp: iface %q: %w", dev, err)
	}
	serverIP, mask, err := ifaceIPv4(dev)
	if err != nil {
		return fmt.Errorf("dhcp: iface %q has no IPv4 address (needed for server-id): %w", dev, err)
	}
	routerIP := net.ParseIP(strings.TrimSpace(cfg.Router)).To4()
	if routerIP == nil {
		// Default to interface IP if not specified.
		routerIP = serverIP
	}
	dnsIPs := parseIPv4List(cfg.DNSServers)
	if len(dnsIPs) == 0 {
		dnsIPs = []net.IP{routerIP}
	}
	leaseSeconds := parseLeaseSeconds(cfg.LeaseSeconds)

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err != nil {
		return fmt.Errorf("dhcp: socket: %w", err)
	}
	defer unix.Close(fd)

	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_BROADCAST, 1)
	_ = unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, dev)

	if err := unix.Bind(fd, &unix.SockaddrInet4{Port: dhcpListenPort}); err != nil {
		return fmt.Errorf("dhcp: bind %s:%d: %w", dev, dhcpListenPort, err)
	}

	buf := make([]byte, 1500)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1, Usec: 0})
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				continue
			}
			return fmt.Errorf("dhcp: recv: %w", err)
		}
		if n <= 0 {
			continue
		}
		req, err := parseRequest(buf[:n])
		if err != nil {
			continue
		}
		if req.msgType != dhcpMsgDiscover && req.msgType != dhcpMsgRequest {
			continue
		}

		assignedIP := net.IP(nil)
		if existing, ok := m.lookupLeaseIP(dev, req.mac); ok {
			assignedIP = net.ParseIP(existing).To4()
		}
		if assignedIP == nil && req.reqIP != nil {
			ip := req.reqIP.To4()
			if ip != nil && ipInPool(ip, pl) && !m.isIPInUse(dev, ip.String()) {
				assignedIP = ip
			}
		}
		if assignedIP == nil {
			ip, err := nextFreeIP(dev, pl, m)
			if err != nil {
				_ = sendNAK(fd, dev, req, serverIP)
				continue
			}
			assignedIP = ip
		}

		switch req.msgType {
		case dhcpMsgDiscover:
			_ = sendOffer(fd, dev, req, assignedIP, serverIP, mask, routerIP, dnsIPs, leaseSeconds, cfg.Domain)
		case dhcpMsgRequest:
			m.upsertLease(dev, req.mac, assignedIP.String(), req.hostname, leaseSeconds)
			_ = sendAck(fd, dev, req, assignedIP, serverIP, mask, routerIP, dnsIPs, leaseSeconds, cfg.Domain)
		}
	}
}

func ifaceIPv4(dev string) (ip net.IP, mask net.IPMask, err error) {
	iface, err := net.InterfaceByName(dev)
	if err != nil {
		return nil, nil, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, nil, err
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet == nil || ipnet.IP == nil {
			continue
		}
		ip4 := ipnet.IP.To4()
		if ip4 == nil {
			continue
		}
		// Skip link-local.
		if strings.HasPrefix(ip4.String(), "169.254.") {
			continue
		}
		return ip4, ipnet.Mask, nil
	}
	return nil, nil, errors.New("no IPv4 address")
}

func ipInPool(ip net.IP, pl pool) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	v := ipToU32(ip4)
	return v >= ipToU32(pl.Start) && v <= ipToU32(pl.End)
}

func parseRequest(pkt []byte) (request, error) {
	var r request
	if len(pkt) < 240 {
		return r, errors.New("short")
	}
	if pkt[0] != dhcpOpRequest || pkt[1] != dhcpHtypeEthernet || pkt[2] != dhcpHlenEthernet {
		return r, errors.New("not dhcp request")
	}
	r.xid = binary.BigEndian.Uint32(pkt[4:8])
	r.flags = binary.BigEndian.Uint16(pkt[10:12])
	mac := pkt[28:34]
	r.mac = net.HardwareAddr(mac).String()
	if binary.BigEndian.Uint32(pkt[236:240]) != dhcpMagicCookie {
		return r, errors.New("no cookie")
	}
	opts := pkt[240:]
	for i := 0; i < len(opts); {
		switch opts[i] {
		case dhcpOptPad:
			i++
			continue
		case dhcpOptEnd:
			i = len(opts)
			continue
		}
		if i+1 >= len(opts) {
			break
		}
		l := int(opts[i+1])
		if i+2+l > len(opts) {
			break
		}
		code := opts[i]
		val := opts[i+2 : i+2+l]
		switch code {
		case dhcpOptMsgType:
			if len(val) == 1 {
				r.msgType = val[0]
			}
		case dhcpOptRequestIP:
			if len(val) == 4 {
				r.reqIP = net.IPv4(val[0], val[1], val[2], val[3])
			}
		case dhcpOptHostName:
			r.hostname = strings.TrimSpace(string(val))
		case dhcpOptClientID:
			r.clientID = append([]byte(nil), val...)
		}
		i += 2 + l
	}
	if r.xid == 0 {
		// Guard against junk.
		return r, errors.New("xid=0")
	}
	return r, nil
}

func sendOffer(fd int, dev string, req request, yiaddr net.IP, serverIP net.IP, mask net.IPMask, routerIP net.IP, dns []net.IP, leaseSeconds int, domain string) error {
	return sendReply(fd, dev, req, dhcpMsgOffer, yiaddr, serverIP, mask, routerIP, dns, leaseSeconds, domain)
}

func sendAck(fd int, dev string, req request, yiaddr net.IP, serverIP net.IP, mask net.IPMask, routerIP net.IP, dns []net.IP, leaseSeconds int, domain string) error {
	return sendReply(fd, dev, req, dhcpMsgAck, yiaddr, serverIP, mask, routerIP, dns, leaseSeconds, domain)
}

func sendNAK(fd int, dev string, req request, serverIP net.IP) error {
	// yiaddr is zero.
	return sendReply(fd, dev, req, dhcpMsgNak, net.IPv4zero, serverIP, nil, nil, nil, 0, "")
}

func sendReply(fd int, dev string, req request, msgType byte, yiaddr net.IP, serverIP net.IP, mask net.IPMask, routerIP net.IP, dns []net.IP, leaseSeconds int, domain string) error {
	yi4 := yiaddr.To4()
	si4 := serverIP.To4()
	if yi4 == nil || si4 == nil {
		return errors.New("ipv4 required")
	}

	// BOOTP fixed header + cookie.
	p := make([]byte, 240)
	p[0] = dhcpOpReply
	p[1] = dhcpHtypeEthernet
	p[2] = dhcpHlenEthernet
	// xid
	binary.BigEndian.PutUint32(p[4:8], req.xid)
	// flags
	binary.BigEndian.PutUint16(p[10:12], req.flags)
	// yiaddr
	copy(p[16:20], yi4)
	// siaddr (server)
	copy(p[20:24], si4)
	// chaddr
	hw, _ := net.ParseMAC(req.mac)
	if len(hw) >= 6 {
		copy(p[28:34], hw[:6])
	} else {
		// best-effort random
		tmp := make([]byte, 6)
		_, _ = rand.Read(tmp)
		copy(p[28:34], tmp)
	}
	binary.BigEndian.PutUint32(p[236:240], dhcpMagicCookie)

	opts := make([]byte, 0, 256)
	opts = appendOpt(opts, dhcpOptMsgType, []byte{msgType})
	opts = appendOpt(opts, dhcpOptServerID, si4)
	if mask != nil && len(mask) == 4 && msgType != dhcpMsgNak {
		opts = appendOpt(opts, dhcpOptSubnetMask, []byte(mask))
	}
	if routerIP != nil && routerIP.To4() != nil && msgType != dhcpMsgNak {
		opts = appendOpt(opts, dhcpOptRouter, routerIP.To4())
	}
	if len(dns) > 0 && msgType != dhcpMsgNak {
		var packed []byte
		for _, ip := range dns {
			if ip4 := ip.To4(); ip4 != nil {
				packed = append(packed, ip4...)
			}
		}
		if len(packed) > 0 {
			opts = appendOpt(opts, dhcpOptDNSServer, packed)
		}
	}
	if domain = strings.TrimSpace(domain); domain != "" && msgType != dhcpMsgNak {
		opts = appendOpt(opts, dhcpOptDomainName, []byte(domain))
	}
	if leaseSeconds > 0 && msgType != dhcpMsgNak {
		ls := make([]byte, 4)
		binary.BigEndian.PutUint32(ls, uint32(leaseSeconds))
		opts = appendOpt(opts, dhcpOptLeaseTime, ls)
	}
	opts = append(opts, dhcpOptEnd)

	pkt := append(p, opts...)
	var bcast [4]byte
	copy(bcast[:], net.IPv4bcast.To4())
	return unix.Sendto(fd, pkt, 0, &unix.SockaddrInet4{Port: dhcpClientPort, Addr: bcast})
}

func appendOpt(dst []byte, code byte, value []byte) []byte {
	if len(value) > 255 {
		value = value[:255]
	}
	dst = append(dst, code, byte(len(value)))
	return append(dst, value...)
}
