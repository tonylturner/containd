//go:build linux

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// suppressKernelRST stops the container kernel from RSTing the RTU's SYN-ACK:
// a raw-socket handshake has no kernel socket, so the kernel would otherwise
// reset it. It scopes the drop to TCP RST toward dst. The returned func
// removes the rule. Requires NET_ADMIN and iptables in the image.
func suppressKernelRST(dst netip.Addr) (func(), error) {
	args := []string{"-w", "-p", "tcp", "-d", dst.String(), "--tcp-flags", "RST", "RST", "-j", "DROP"}
	add := append([]string{"-A", "OUTPUT"}, args...)
	if out, err := exec.Command("iptables", add...).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("install RST drop: %v: %s", err, out)
	}
	return func() {
		del := append([]string{"-D", "OUTPUT"}, args...)
		_ = exec.Command("iptables", del...).Run()
	}, nil
}

// rawSession is a minimal user-space TCP sender over raw IPv4 sockets. It owns
// its sequence numbers, so the harness can inject a later segment of a session
// after that session should be gone (the stale-retransmit case). It is not a
// general TCP stack: it tracks only what the lib60870 RTU needs to accept a
// STARTDT and a command.
type rawSession struct {
	srcIP, dstIP     [4]byte
	srcPort, dstPort uint16
	sendFD, recvFD   int
	seq, iss         uint32

	mu     sync.Mutex
	ackVal uint32
	done   bool
}

func openRawSession(src, dst netip.AddrPort) (*rawSession, error) {
	sendFD, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("raw send socket: %w", err)
	}
	if err := unix.SetsockoptInt(sendFD, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		unix.Close(sendFD)
		return nil, fmt.Errorf("IP_HDRINCL: %w", err)
	}
	recvFD, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_TCP)
	if err != nil {
		unix.Close(sendFD)
		return nil, fmt.Errorf("raw recv socket: %w", err)
	}
	tv := unix.Timeval{Usec: 200000}
	_ = unix.SetsockoptTimeval(recvFD, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	s := &rawSession{
		srcIP:   src.Addr().As4(),
		dstIP:   dst.Addr().As4(),
		srcPort: src.Port(),
		dstPort: dst.Port(),
		sendFD:  sendFD,
		recvFD:  recvFD,
		iss:     uint32(time.Now().UnixNano()),
	}
	s.seq = s.iss
	// A background reader drains our flow's segments and tracks the peer's
	// sequence, so the handshake does not depend on reading at the right
	// instant. It stops when close() shuts the socket down.
	go s.readLoop()
	return s, nil
}

// readLoop advances ack to the highest received sequence+length for our flow,
// so our ACKs stay in the RTU's window. It exits when the socket is closed.
func (s *rawSession) readLoop() {
	buf := make([]byte, 65535)
	for {
		n, err := unix.Read(s.recvFD, buf)
		s.mu.Lock()
		stop := s.done
		s.mu.Unlock()
		if stop {
			return
		}
		if err != nil || n < 40 {
			continue
		}
		pkt := buf[:n]
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || n < ihl+20 || pkt[9] != 6 {
			continue
		}
		if !ipEq(pkt[12:16], s.dstIP) || !ipEq(pkt[16:20], s.srcIP) {
			continue
		}
		tcp := pkt[ihl:]
		if binary.BigEndian.Uint16(tcp[0:]) != s.dstPort || binary.BigEndian.Uint16(tcp[2:]) != s.srcPort {
			continue
		}
		theirSeq := binary.BigEndian.Uint32(tcp[4:])
		dataOff := int(tcp[12]>>4) * 4
		next := theirSeq + uint32(len(tcp)-dataOff)
		if tcp[13]&tcpSYN != 0 {
			next++ // SYN consumes a sequence number
		}
		s.mu.Lock()
		if s.ackVal == 0 || seqGreater(next, s.ackVal) {
			s.ackVal = next
		}
		s.mu.Unlock()
	}
}

func (s *rawSession) ack() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ackVal
}

func (s *rawSession) close() {
	s.mu.Lock()
	s.done = true
	s.mu.Unlock()
	if s.recvFD >= 0 {
		unix.Close(s.recvFD)
		s.recvFD = -1
	}
	if s.sendFD >= 0 {
		unix.Close(s.sendFD)
		s.sendFD = -1
	}
}

func (s *rawSession) sendAt(seq uint32, flags byte, payload []byte) error {
	pkt := buildIPv4TCP(s.srcIP, s.dstIP, s.srcPort, s.dstPort, seq, s.ack(), flags, 65535, payload)
	var to unix.SockaddrInet4
	to.Addr = s.dstIP
	to.Port = int(s.dstPort)
	return unix.Sendto(s.sendFD, pkt, 0, &to)
}

func ipEq(b []byte, want [4]byte) bool {
	return b[0] == want[0] && b[1] == want[1] && b[2] == want[2] && b[3] == want[3]
}

// connect performs the three-way handshake and leaves seq at the first data
// byte. It waits for the reader goroutine to see the SYN-ACK, retransmitting
// the SYN if the first is lost or the accept is slow.
func (s *rawSession) connect() error {
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if err := s.sendAt(s.seq, tcpSYN, nil); err != nil {
			return fmt.Errorf("send SYN: %w", err)
		}
		for i := 0; i < 5; i++ {
			time.Sleep(100 * time.Millisecond)
			if s.ack() != 0 {
				s.seq = s.iss + 1
				return s.sendAt(s.seq, tcpACK, nil)
			}
		}
	}
	return fmt.Errorf("no SYN-ACK from %d.%d.%d.%d:%d", s.dstIP[0], s.dstIP[1], s.dstIP[2], s.dstIP[3], s.dstPort)
}

// write sends payload as one PSH+ACK segment and advances seq past it.
func (s *rawSession) write(payload []byte) error {
	if err := s.sendAt(s.seq, tcpPSH|tcpACK, payload); err != nil {
		return err
	}
	s.seq += uint32(len(payload))
	time.Sleep(300 * time.Millisecond)
	return nil
}

func localIPv4For(dst netip.AddrPort) (netip.Addr, error) {
	c, err := net.Dial("udp", dst.String())
	if err != nil {
		return netip.Addr{}, err
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap(), nil
}

// staleRetransmit drives the §10.2 stale-retransmit case. Incarnation 1 (from
// port lport) handshakes, STARTDTs and sends a forbidden command to -ioa. Then
// a second raw session (port lport+1) handshakes and STARTDTs — the "new
// handshake". Finally a lone segment of incarnation 1, at its next sequence
// number, injects a fresh forbidden command to ioa+1: the stale retransmit.
// The harness reads the RTU state to decide whether that stale segment was
// delivered; this tool reports what it sent.
func staleRetransmit(o options) result {
	r := result{name: o.scenario, socket: "raw"}
	dst, err := netip.ParseAddrPort(o.addr)
	if err != nil {
		r.fatal = fmt.Errorf("addr: %w", err)
		return r
	}
	localIP, err := localIPv4For(dst)
	if err != nil {
		r.fatal = fmt.Errorf("local IP: %w", err)
		return r
	}
	restore, err := suppressKernelRST(dst.Addr())
	if err != nil {
		r.fatal = err
		return r
	}
	defer restore()
	port1 := uint16(o.lport)
	if port1 == 0 {
		port1 = 40405
	}

	s1, err := openRawSession(netip.AddrPortFrom(localIP, port1), dst)
	if err != nil {
		r.fatal = err
		return r
	}
	defer s1.close()
	if err := s1.connect(); err != nil {
		r.fatal = fmt.Errorf("incarnation 1 connect: %w", err)
		return r
	}
	if err := s1.write(startdtAct); err != nil {
		r.fatal = fmt.Errorf("incarnation 1 STARTDT: %w", err)
		return r
	}
	forbidden1 := iFrame(0, 0, doubleCommand(o.ca, o.ioa, byte(o.dcs), true))
	staleSeq := s1.seq + uint32(len(forbidden1)) // where the stale segment will sit
	if err := s1.write(forbidden1); err != nil {
		r.fatal = fmt.Errorf("incarnation 1 forbidden command: %w", err)
		return r
	}
	r.sent += len(forbidden1)

	// A second, new handshake from another port (the client "reconnects").
	s2, err := openRawSession(netip.AddrPortFrom(localIP, port1+1), dst)
	if err != nil {
		r.fatal = fmt.Errorf("incarnation 2 open: %w", err)
		return r
	}
	defer s2.close()
	if err := s2.connect(); err != nil {
		r.fatal = fmt.Errorf("incarnation 2 connect: %w", err)
		return r
	}
	if err := s2.write(startdtAct); err != nil {
		r.fatal = fmt.Errorf("incarnation 2 STARTDT: %w", err)
		return r
	}

	// The stale retransmit: a later segment of incarnation 1, carrying a fresh
	// forbidden command to a distinct point so its delivery is unambiguous.
	staleCmd := iFrame(1, 0, doubleCommand(o.ca, o.ioa+1, byte(o.dcs), true))
	if err := s1.sendAt(staleSeq, tcpPSH|tcpACK, staleCmd); err != nil {
		r.fatal = fmt.Errorf("stale retransmit: %w", err)
		return r
	}
	r.sent += len(staleCmd)
	r.note = fmt.Sprintf("incarnation1 port %d ioa %d; incarnation2 port %d; stale segment seq %d ioa %d", port1, o.ioa, port1+1, staleSeq, o.ioa+1)
	time.Sleep(500 * time.Millisecond)
	return r
}
