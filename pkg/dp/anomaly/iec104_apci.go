// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package anomaly

import "time"

const (
	IEC104DataWhileStopped = "iec104_data_while_stopped"
	IEC104SendSequence     = "iec104_send_sequence"
	IEC104AckSequence      = "iec104_ack_sequence"
	IEC104TestTimeout      = "iec104_test_timeout"
	IEC104T1               = 15 * time.Second
	iec104SequenceMask     = 32767
)

// IEC104APCIFrame is one ordered, TCP-deduplicated APCI observation.
// Direction is 0 for client to server and 1 for server to client.
type IEC104APCIFrame struct {
	Direction int
	Format    string
	Send      uint16
	Receive   uint16
	UFunction string
}

// IEC104APCIFinding contains protocol evidence, without engine/session identity.
type IEC104APCIFinding struct {
	Type       string
	Message    string
	Direction  int
	Attributes map[string]any
}

// IEC104APCI observes one connection from its SYN. Its zero value is ready
// for use. Storage is constant: two sequence windows and two TESTFR timers.
// The owner serializes calls and discards the state when observation ends.
type IEC104APCI struct {
	started         bool
	stoppedReported bool // re-armed only by STARTDT con
	dirs            [2]iec104APCIDirection
}

type iec104APCIDirection struct {
	next    uint16 // next unsent N(S)
	acked   uint16 // last N(R) received from the peer
	testAt  time.Time
	testing bool
}

// Observe advances the analyzer without making any enforcement decision.
// Invalid N(S) is reported then rebased to the observed next sequence to avoid
// cascading gap reports. Invalid ACKs never advance the acknowledged boundary.
func (s *IEC104APCI) Observe(f IEC104APCIFrame, now time.Time) []IEC104APCIFinding {
	if f.Direction < 0 || f.Direction > 1 {
		return nil
	}
	out := s.Expire(now)
	d, peer := &s.dirs[f.Direction], &s.dirs[1-f.Direction]
	switch f.Format {
	case "U":
		switch f.UFunction {
		case "startdt_con":
			s.started = true
			s.stoppedReported = false
		case "stopdt_con":
			s.started = false
		case "testfr_act":
			// Keep the oldest outstanding activation's deadline.
			if !d.testing {
				d.testAt, d.testing = now, true
			}
		case "testfr_con":
			peer.testing = false
		}
	case "I", "S":
		if f.Format == "I" {
			if !s.started && !s.stoppedReported {
				s.stoppedReported = true
				out = append(out, IEC104APCIFinding{
					Type: IEC104DataWhileStopped, Direction: f.Direction,
					Message: "IEC 104 I-frame before STARTDT confirmation or after STOPDT confirmation",
				})
			}
			if f.Send != d.next {
				out = append(out, IEC104APCIFinding{
					Type: IEC104SendSequence, Direction: f.Direction,
					Message:    "IEC 104 N(S) gap or backwards step",
					Attributes: map[string]any{"send_sequence": f.Send, "expected_send_sequence": d.next},
				})
			}
			d.next = (f.Send + 1) & iec104SequenceMask
		}
		// The ACK belongs to the opposite direction's send window. Compare
		// distances from last acked, not numeric order (32767 wraps to 0).
		if (f.Receive-peer.acked)&iec104SequenceMask > (peer.next-peer.acked)&iec104SequenceMask {
			out = append(out, IEC104APCIFinding{
				Type: IEC104AckSequence, Direction: f.Direction,
				Message: "IEC 104 N(R) outside the acknowledged-to-next-unsent window",
				Attributes: map[string]any{
					"receive_sequence": f.Receive, "last_acked": peer.acked, "next_unsent": peer.next,
				},
			})
		} else {
			peer.acked = f.Receive
		}
	}
	return out
}

// Expire reports each unanswered TESTFR act once at t1, even without packets.
func (s *IEC104APCI) Expire(now time.Time) []IEC104APCIFinding {
	var out []IEC104APCIFinding
	for dir := range s.dirs {
		d := &s.dirs[dir]
		if d.testing && now.Sub(d.testAt) >= IEC104T1 {
			d.testing = false
			out = append(out, IEC104APCIFinding{
				Type: IEC104TestTimeout, Direction: dir,
				Message:    "IEC 104 TESTFR activation unconfirmed within t1",
				Attributes: map[string]any{"t1_seconds": int(IEC104T1.Seconds()), "u_function": "testfr_act"},
			})
		}
	}
	return out
}
