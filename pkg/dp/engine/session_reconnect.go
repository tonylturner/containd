// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
)

// Serialize the old incarnation's reset I/O with tuple reuse without holding
// the session lock across I/O or introducing another TCP state owner.
func (t *sessionTable) resetWork(s *trackedSession, work, cancelled func()) func() {
	return func() {
		t.mu.Lock()
		key := sessionKey{client: s.client, server: s.server}
		if t.sessions[key] != s || s.state != sessionAborted || s.retireAfterReset {
			t.mu.Unlock()
			if cancelled != nil {
				cancelled()
			}
			return
		}
		done := make(chan struct{})
		s.resetIO = done
		t.mu.Unlock()
		defer func() {
			t.mu.Lock()
			s.resetIO = nil
			var acts sessionActions
			if s.retireAfterReset && t.sessions[key] == s {
				acts = t.deleteLocked(key, s)
			}
			close(done)
			t.mu.Unlock()
			t.finish(acts)
		}()
		work()
	}
}

func replacementHandshake(s *trackedSession, dir int, pkt capture.Packet) bool {
	if s.retireAfterReset {
		return true
	}
	if dir == sessionDirClient && isSYN(pkt.TCP.Flags) && handshakeMarked(pkt) {
		c := s.dirs[sessionDirClient]
		return c == nil || c.isn != pkt.TCP.Seq
	}
	return s.next != nil && dir == sessionDirSrv && pkt.TCP.Flags&(capture.TCPFlagSYN|capture.TCPFlagACK) == capture.TCPFlagSYN|capture.TCPFlagACK
}

// A new SYN is only a proposal. Its validated peer SYN-ACK, not that proposal,
// retires old grants/holds and publishes the replacement incarnation.
func (t *sessionTable) replacementLocked(s *trackedSession, dir int, pkt capture.Packet, now time.Time) (sessionResult, bool) {
	n := s.next
	if n == nil {
		return sessionResult{}, false
	}
	if pkt.TCP.Flags&capture.TCPFlagSYN == 0 && refuses(n, dir, pkt) {
		s.next = nil
		n.releaseInspection()
		return accepted(reasonIECClosed), true
	}
	if dir != sessionDirSrv || pkt.TCP.Flags&(capture.TCPFlagSYN|capture.TCPFlagACK) != capture.TCPFlagSYN|capture.TCPFlagACK ||
		pkt.TCP.Ack != n.dirs[sessionDirClient].isn+1 || len(pkt.Payload) != 0 {
		return sessionResult{}, false
	}
	if err := t.allocateDirLocked(n, sessionDirSrv, pkt.TCP.Seq); err != nil {
		s.next = nil
		n.releaseInspection()
		return t.admissionLimitLocked(n.mode), true
	}
	n.state, n.lastSeen = sessionEstablished, now
	s.next = nil
	res := accepted(reasonIECAccept)
	res.decision.Resolved = t.dropHeldLocked(s, -1)
	if s.state == sessionAborted {
		t.tombstones--
		t.removeDenialLocked(s)
	}
	t.dpi.EndStream(s.id)
	res.acts.merge(t.iecAdapter.endLocked(t, s))
	res.acts.retired = true
	t.sessions[sessionKey{client: s.client, server: s.server}] = n
	s.releaseInspection()
	return res, true
}
