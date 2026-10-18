// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package capture

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

type worker struct {
	iface   string
	cfg     Config
	handler Handler
}

func (w *worker) run(ctx context.Context) error {
	iface, err := net.InterfaceByName(w.iface)
	if err != nil {
		return fmt.Errorf("unknown interface %q: %w", w.iface, err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons16(unix.ETH_P_ALL)))
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.SetNonblock(fd, true); err != nil {
		return err
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons16(unix.ETH_P_ALL), Ifindex: iface.Index}); err != nil {
		return err
	}
	if w.cfg.BufferMB > 0 {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, w.cfg.BufferMB*1024*1024)
	}
	if w.cfg.Promisc {
		_ = unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &unix.PacketMreq{
			Ifindex: int32(iface.Index),
			Type:    unix.PACKET_MR_PROMISC,
		})
	}
	buf := make([]byte, w.cfg.Snaplen)
	for {
		if ctx.Err() != nil {
			return nil
		}
		// Poll, rather than a blocking Recvfrom, bounds cancellation latency
		// on a quiet interface to the 250ms poll timeout without a socket
		// closer goroutine racing this worker's descriptor lifetime.
		timeout := 250
		pollfds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(pollfds, timeout)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return err
		}
		if n == 0 || pollfds[0].Revents&unix.POLLIN == 0 {
			continue
		}
		rn, from, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
				continue
			}
			return err
		}
		if rn <= 0 || outgoingPacket(from) {
			continue
		}
		pkt, ok := decodePacket(w.iface, buf[:rn])
		if !ok {
			continue
		}
		// AF_PACKET is observational: the decision is not applied.
		_ = w.handler(pkt)
	}
}

// outgoingPacket excludes local transmit copies, including forwarded packets
// after masquerade. Ingress capture sees each wire direction before NAT once.
func outgoingPacket(from unix.Sockaddr) bool {
	ll, ok := from.(*unix.SockaddrLinklayer)
	return ok && ll.Pkttype == unix.PACKET_OUTGOING
}

// decodePacket strips the Ethernet header and decodes the IP packet with
// the shared raw-IP decoder. The IP version must match the EtherType.
func decodePacket(iface string, data []byte) (Packet, bool) {
	ethType, offset, ok := parseEthernet(data)
	if !ok {
		return Packet{}, false
	}
	ip := data[offset:]
	var version byte
	switch ethType {
	case 0x0800:
		version = 4
	case 0x86dd:
		version = 6
	default:
		return Packet{}, false
	}
	if len(ip) < 1 || ip[0]>>4 != version {
		return Packet{}, false
	}
	pkt, ok := decodeIP(ip)
	if !ok {
		return Packet{}, false
	}
	pkt.Timestamp = time.Now().UTC()
	pkt.Interface = iface
	return pkt, true
}

func parseEthernet(data []byte) (uint16, int, bool) {
	if len(data) < 14 {
		return 0, 0, false
	}
	ethType := binary.BigEndian.Uint16(data[12:14])
	offset := 14
	if ethType == 0x8100 || ethType == 0x88a8 {
		if len(data) < 18 {
			return 0, 0, false
		}
		ethType = binary.BigEndian.Uint16(data[16:18])
		offset = 18
	}
	return ethType, offset, true
}

func htons16(v uint16) uint16 {
	return (v<<8)&0xff00 | v>>8
}
