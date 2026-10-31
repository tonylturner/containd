// SPDX-License-Identifier: Apache-2.0

package dpi_test

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/iec104"
	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
)

func TestFlowFramerBothDirections(t *testing.T) {
	for _, tc := range []struct {
		client, server uint16
		protocol       string
		request, reply []byte
	}{
		{502, 2404, "iec104", []byte{0x68, 4, 7, 0, 0, 0}, []byte{0x68, 4, 11, 0, 0, 0}},
		{2404, 502, "modbus", []byte{0, 1, 0, 0, 0, 6, 1, 3, 0, 0, 0, 2}, []byte{0, 1, 0, 0, 0, 7, 1, 3, 4, 0, 10, 0, 11}},
		{41000, 502, "modbus", []byte{0, 1, 0, 0, 0, 6, 1, 3, 0, 0, 0, 2}, []byte{0, 1, 0, 0, 0, 7, 1, 3, 4, 0, 10, 0, 11}},
	} {
		for _, replyFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d-%d/reply-first=%t", tc.client, tc.server, replyFirst), func(t *testing.T) {
				m := dpi.NewManager(modbus.NewDecoder(), iec104.NewDecoder())
				key := flow.Key{SrcIP: net.ParseIP("10.0.0.1"), DstIP: net.ParseIP("10.0.0.2"),
					SrcPort: tc.client, DstPort: tc.server, Proto: 6}
				states := []*flow.State{flow.NewState(key, time.Now()), flow.NewState(key.Reversed(), time.Now())}
				if matches, committed := m.CommittedProtocol(states[0], tc.protocol); !matches || committed {
					t.Fatalf("prospective owner: matches=%t committed=%t", matches, committed)
				}
				packets := []*dpi.ParsedPacket{
					{Proto: "tcp", HasOffset: true, Session: "s", Dir: dpi.ClientToServer, Payload: tc.request},
					{Proto: "tcp", HasOffset: true, Session: "s", Dir: dpi.ServerToClient, Payload: tc.reply},
				}
				order := []int{0, 1}
				if replyFirst {
					order = []int{1, 0}
				}
				for _, i := range order {
					res := m.Inspect(states[i], packets[i])
					if res.Err != nil || res.Proto != tc.protocol || len(res.Frames) != 1 || len(res.Events) != 1 || res.Events[0].Proto != tc.protocol {
						t.Fatalf("direction %d: %+v", i, res)
					}
					for _, state := range states {
						for _, protocol := range []string{"iec104", "modbus"} {
							matches, committed := m.CommittedProtocol(state, protocol)
							if !committed || matches != (protocol == tc.protocol) {
								t.Fatalf("direction %d owner %s: matches=%t committed=%t", i, protocol, matches, committed)
							}
						}
					}
				}
				m.EndStream("s")
			})
		}
	}
}
