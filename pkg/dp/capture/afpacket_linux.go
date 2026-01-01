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
		rn, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
				continue
			}
			return err
		}
		if rn <= 0 {
			continue
		}
		pkt, ok := decodePacket(w.iface, buf[:rn])
		if !ok {
			continue
		}
		w.handler(pkt)
	}
}

func decodePacket(iface string, data []byte) (Packet, bool) {
	ethType, offset, ok := parseEthernet(data)
	if !ok {
		return Packet{}, false
	}
	switch ethType {
	case 0x0800:
		return decodeIPv4(iface, data[offset:])
	case 0x86dd:
		return decodeIPv6(iface, data[offset:])
	default:
		return Packet{}, false
	}
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

func decodeIPv4(iface string, data []byte) (Packet, bool) {
	if len(data) < 20 {
		return Packet{}, false
	}
	version := data[0] >> 4
	if version != 4 {
		return Packet{}, false
	}
	ihl := int(data[0]&0x0f) * 4
	if ihl < 20 || len(data) < ihl {
		return Packet{}, false
	}
	proto := data[9]
	src := net.IPv4(data[12], data[13], data[14], data[15])
	dst := net.IPv4(data[16], data[17], data[18], data[19])
	return decodeL4(iface, proto, src, dst, data[ihl:])
}

func decodeIPv6(iface string, data []byte) (Packet, bool) {
	if len(data) < 40 {
		return Packet{}, false
	}
	version := data[0] >> 4
	if version != 6 {
		return Packet{}, false
	}
	proto := data[6]
	src := net.IP(append([]byte(nil), data[8:24]...))
	dst := net.IP(append([]byte(nil), data[24:40]...))
	return decodeL4(iface, proto, src, dst, data[40:])
}

func decodeL4(iface string, proto uint8, src, dst net.IP, data []byte) (Packet, bool) {
	switch proto {
	case 6:
		sport, dport, payload, ok := decodeTCP(data)
		if !ok {
			return Packet{}, false
		}
		return Packet{
			Timestamp: time.Now().UTC(),
			Interface: iface,
			SrcIP:     src,
			DstIP:     dst,
			SrcPort:   sport,
			DstPort:   dport,
			Proto:     proto,
			Transport: "tcp",
			Payload:   payload,
		}, true
	case 17:
		sport, dport, payload, ok := decodeUDP(data)
		if !ok {
			return Packet{}, false
		}
		return Packet{
			Timestamp: time.Now().UTC(),
			Interface: iface,
			SrcIP:     src,
			DstIP:     dst,
			SrcPort:   sport,
			DstPort:   dport,
			Proto:     proto,
			Transport: "udp",
			Payload:   payload,
		}, true
	default:
		return Packet{}, false
	}
}

func decodeTCP(data []byte) (uint16, uint16, []byte, bool) {
	if len(data) < 20 {
		return 0, 0, nil, false
	}
	sport := binary.BigEndian.Uint16(data[0:2])
	dport := binary.BigEndian.Uint16(data[2:4])
	off := int(data[12]>>4) * 4
	if off < 20 || len(data) < off {
		return 0, 0, nil, false
	}
	payload := append([]byte(nil), data[off:]...)
	return sport, dport, payload, true
}

func decodeUDP(data []byte) (uint16, uint16, []byte, bool) {
	if len(data) < 8 {
		return 0, 0, nil, false
	}
	sport := binary.BigEndian.Uint16(data[0:2])
	dport := binary.BigEndian.Uint16(data[2:4])
	payload := append([]byte(nil), data[8:]...)
	return sport, dport, payload, true
}

func htons16(v uint16) uint16 {
	return (v<<8)&0xff00 | v>>8
}
