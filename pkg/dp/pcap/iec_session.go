// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package pcap

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"strconv"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

const iec104Port = 2404

// offlineSessions tracks IEC104 sessions from their SYN in one offline
// analysis run, as the live engine does, so IEC104 is parsed only with
// absolute offsets and incarnation IDs. A session not
// captured from its SYN is not parsed.
type offlineSessions struct {
	runID string
	seq   uint64
	byKey map[offlineKey]*offlineSession
}

type offlineKey struct{ client, server string }

type offlineSession struct {
	id   string
	dirs [2]*flow.SeqSpace // client→server, server→client
	fin  [2]bool
}

func newOfflineSessions() *offlineSessions {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("pcap: run ID: " + err.Error())
	}
	return &offlineSessions{runID: hex.EncodeToString(b[:]), byKey: make(map[offlineKey]*offlineSession)}
}

func endpoint(ip net.IP, port uint16) string {
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
}

// annotate fills the session fields of an IEC104 packet. iec reports a
// TCP packet to or from port 2404; parse reports whether it may be parsed.
func (o *offlineSessions) annotate(mgr *dpi.Manager, pkt capture.Packet, parsed *dpi.ParsedPacket) (iec, parse bool) {
	if pkt.Proto != 6 || (pkt.SrcPort != iec104Port && pkt.DstPort != iec104Port) || !pkt.TCP.Valid {
		return false, false
	}
	src, dst := endpoint(pkt.SrcIP, pkt.SrcPort), endpoint(pkt.DstIP, pkt.DstPort)
	f := pkt.TCP.Flags
	if f&capture.TCPFlagSYN != 0 && f&capture.TCPFlagACK == 0 && pkt.DstPort == iec104Port {
		o.seq++
		c2s := flow.NewSeqSpace(pkt.TCP.Seq)
		o.byKey[offlineKey{client: src, server: dst}] = &offlineSession{
			id:   eventfields.SessionID(o.runID, o.seq),
			dirs: [2]*flow.SeqSpace{&c2s},
		}
		return true, false
	}
	key, dir := offlineKey{client: src, server: dst}, 0
	s := o.byKey[key]
	if s == nil {
		key, dir = offlineKey{client: dst, server: src}, 1
		s = o.byKey[key]
	}
	if s == nil {
		return true, false
	}
	if dir == 1 && f&capture.TCPFlagSYN != 0 && s.dirs[1] == nil && pkt.TCP.Ack == s.dirs[0].Seq(0) {
		s2c := flow.NewSeqSpace(pkt.TCP.Seq)
		s.dirs[1] = &s2c
		return true, false
	}
	if s.dirs[1] == nil || f&capture.TCPFlagSYN != 0 {
		return true, false
	}
	off := s.dirs[dir].Offset(pkt.TCP.Seq)
	if f&capture.TCPFlagFIN != 0 {
		s.fin[dir] = true
	}
	if f&capture.TCPFlagRST != 0 || (s.fin[0] && s.fin[1]) {
		mgr.EndStream(s.id)
		delete(o.byKey, key)
		return true, false
	}
	if off < 0 || len(pkt.Payload) == 0 {
		return true, false
	}
	s.dirs[dir].Advance(off + int64(len(pkt.Payload)))
	parsed.HasOffset, parsed.Offset, parsed.Session = true, off, s.id
	parsed.Dir = dpi.ClientToServer
	if dir == 1 {
		parsed.Dir = dpi.ServerToClient
	}
	return true, true
}
