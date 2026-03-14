// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package netcfg

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

type WireGuardStatus struct {
	Interface  string                `json:"interface"`
	Present    bool                  `json:"present"`
	PublicKey  string                `json:"publicKey,omitempty"` // base64
	ListenPort int                   `json:"listenPort,omitempty"`
	Peers      []WireGuardPeerStatus `json:"peers,omitempty"`
}

type WireGuardPeerStatus struct {
	PublicKey     string   `json:"publicKey"` // base64
	Endpoint      string   `json:"endpoint,omitempty"`
	LastHandshake string   `json:"lastHandshake,omitempty"` // RFC3339Nano UTC
	RxBytes       uint64   `json:"rxBytes,omitempty"`
	TxBytes       uint64   `json:"txBytes,omitempty"`
	AllowedIPs    []string `json:"allowedIPs,omitempty"`
}

// GetWireGuardStatus returns kernel WireGuard runtime status for a given interface name.
// It uses generic netlink ("wireguard" family) and does not shell out to `wg`.
func GetWireGuardStatus(ctx context.Context, ifaceName string) (WireGuardStatus, error) {
	ifaceName = strings.TrimSpace(ifaceName)
	if ifaceName == "" {
		ifaceName = "wg0"
	}
	status := WireGuardStatus{Interface: ifaceName}

	nic, err := net.InterfaceByName(ifaceName)
	if err != nil || nic == nil {
		return status, nil
	}
	status.Present = true

	fd, err := openWireGuardNetlinkSocket()
	if err != nil {
		return status, err
	}
	defer unix.Close(fd)

	familyID, err := genlFamilyID(ctx, fd, wgGenlName)
	if err != nil {
		return status, err
	}

	seq := atomic.AddUint32(&nlSeq, 1)
	b := buildWireGuardStatusRequest(seq, familyID, nic.Index)
	if err := unix.Sendto(fd, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return status, fmt.Errorf("wireguard: send: %w", err)
	}

	return collectWireGuardStatus(ctx, fd, seq, &status)
}

func openWireGuardNetlinkSocket() (int, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_GENERIC)
	if err != nil {
		return 0, fmt.Errorf("wireguard: netlink generic socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return 0, fmt.Errorf("wireguard: netlink bind: %w", err)
	}
	return fd, nil
}

func buildWireGuardStatusRequest(seq uint32, familyID, ifIndex int) []byte {
	var req bytes.Buffer
	_ = binary.Write(&req, binary.LittleEndian, unix.NlMsghdr{
		Type:  uint16(familyID),
		Flags: unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_DUMP,
		Seq:   seq,
		Pid:   uint32(unix.Getpid()),
	})
	_ = binary.Write(&req, binary.LittleEndian, genlMsgHdr{Cmd: wgCmdGetDevice, Version: wgGenlVersion})

	ifi := make([]byte, 4)
	binary.LittleEndian.PutUint32(ifi, uint32(ifIndex))
	addNLAttr(&req, wgDeviceAIfindex, ifi)

	b := req.Bytes()
	(*unix.NlMsghdr)(unsafe.Pointer(&b[0])).Len = uint32(len(b))
	return b
}

func collectWireGuardStatus(ctx context.Context, fd int, seq uint32, status *WireGuardStatus) (WireGuardStatus, error) {
	deadline := wireGuardStatusDeadline(ctx)
	buf := make([]byte, 1<<16)
	for {
		if time.Now().After(deadline) {
			return *status, context.DeadlineExceeded
		}
		if err := setWireGuardRecvDeadline(fd, deadline); err != nil {
			return *status, err
		}
		done, err := recvWireGuardStatusBatch(fd, buf, seq, status)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				continue
			}
			return *status, err
		}
		if done {
			return *status, nil
		}
	}
}

func wireGuardStatusDeadline(ctx context.Context) time.Time {
	deadline := time.Now().Add(2 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		return dl
	}
	return deadline
}

func setWireGuardRecvDeadline(fd int, deadline time.Time) error {
	tv := unix.NsecToTimeval(time.Until(deadline).Nanoseconds())
	return unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
}

func recvWireGuardStatusBatch(fd int, buf []byte, seq uint32, status *WireGuardStatus) (bool, error) {
	n, _, err := unix.Recvfrom(fd, buf, 0)
	if err != nil {
		return false, err
	}
	msgs, err := syscall.ParseNetlinkMessage(buf[:n])
	if err != nil {
		return false, err
	}
	for _, m := range msgs {
		done, err := handleWireGuardStatusMessage(m, seq, status)
		if err != nil || done {
			return done, err
		}
	}
	return false, nil
}

func handleWireGuardStatusMessage(msg syscall.NetlinkMessage, seq uint32, status *WireGuardStatus) (bool, error) {
	if msg.Header.Seq != seq {
		return false, nil
	}
	switch msg.Header.Type {
	case unix.NLMSG_DONE:
		return true, nil
	case unix.NLMSG_ERROR:
		return false, netlinkMessageError(msg.Data)
	default:
		if len(msg.Data) < 4 {
			return false, nil
		}
		parseWireGuardDeviceAttrs(status, msg.Data[4:])
		return false, nil
	}
}

func parseWireGuardDeviceAttrs(out *WireGuardStatus, attrs []byte) {
	if out == nil {
		return
	}
	for _, a := range parseNetlinkAttrs(attrs) {
		t := a.Type &^ nlaNested
		switch t {
		case wgDeviceAPublicKey:
			if len(a.Value) == 32 {
				out.PublicKey = base64.StdEncoding.EncodeToString(a.Value)
			}
		case wgDeviceAListenPort:
			if len(a.Value) >= 2 {
				out.ListenPort = int(binary.LittleEndian.Uint16(a.Value[:2]))
			}
		case wgDeviceAPeers:
			out.Peers = parseWireGuardPeers(a.Value)
		}
	}
}

func parseWireGuardPeers(b []byte) []WireGuardPeerStatus {
	peers := []WireGuardPeerStatus{}
	for _, p := range parseNetlinkAttrs(b) {
		// Each peer is a nested attr.
		if p.Type&nlaNested == 0 {
			continue
		}
		ps := WireGuardPeerStatus{}
		for _, a := range parseNetlinkAttrs(p.Value) {
			t := a.Type &^ nlaNested
			switch t {
			case wgPeerAPublicKey:
				if len(a.Value) == 32 {
					ps.PublicKey = base64.StdEncoding.EncodeToString(a.Value)
				}
			case wgPeerAEndpoint:
				ps.Endpoint = decodeSockaddr(a.Value)
			case wgPeerALastHandshakeTime:
				ps.LastHandshake = decodeTimespec(a.Value)
			case wgPeerARxBytes:
				if len(a.Value) >= 8 {
					ps.RxBytes = binary.LittleEndian.Uint64(a.Value[:8])
				}
			case wgPeerATxBytes:
				if len(a.Value) >= 8 {
					ps.TxBytes = binary.LittleEndian.Uint64(a.Value[:8])
				}
			case wgPeerAAllowedIPs:
				ps.AllowedIPs = decodeAllowedIPs(a.Value)
			}
		}
		if ps.PublicKey != "" {
			peers = append(peers, ps)
		}
	}
	return peers
}

func decodeAllowedIPs(b []byte) []string {
	out := []string{}
	for _, n := range parseNetlinkAttrs(b) {
		if n.Type&nlaNested == 0 {
			continue
		}
		var (
			family uint16
			ip     net.IP
			mask   uint8
		)
		for _, a := range parseNetlinkAttrs(n.Value) {
			t := a.Type &^ nlaNested
			switch t {
			case wgAllowedipAFamily:
				if len(a.Value) >= 2 {
					family = binary.LittleEndian.Uint16(a.Value[:2])
				}
			case wgAllowedipAIpaddr:
				if len(a.Value) >= 4 {
					ip = net.IP(append([]byte(nil), a.Value...))
				}
			case wgAllowedipACidrMask:
				if len(a.Value) >= 1 {
					mask = a.Value[0]
				}
			}
		}
		if family == unix.AF_INET && ip != nil {
			ip = ip.To4()
		}
		if ip == nil {
			continue
		}
		out = append(out, fmt.Sprintf("%s/%d", ip.String(), mask))
	}
	return out
}

func decodeTimespec(b []byte) string {
	// Kernel uses a timespec-like struct: 16 bytes (sec int64, nsec int64), little-endian.
	if len(b) < 16 {
		return ""
	}
	sec := int64(binary.LittleEndian.Uint64(b[0:8]))
	nsec := int64(binary.LittleEndian.Uint64(b[8:16]))
	if sec <= 0 {
		return ""
	}
	if nsec < 0 {
		nsec = 0
	}
	return time.Unix(sec, nsec).UTC().Format(time.RFC3339Nano)
}

func decodeSockaddr(b []byte) string {
	// Supports sockaddr_in only for now (16 bytes).
	if len(b) < 8 {
		return ""
	}
	family := binary.LittleEndian.Uint16(b[0:2])
	if family != unix.AF_INET {
		return ""
	}
	port := binary.BigEndian.Uint16(b[2:4])
	ip := net.IPv4(b[4], b[5], b[6], b[7])
	return fmt.Sprintf("%s:%d", ip.String(), port)
}
