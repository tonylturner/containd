// SPDX-License-Identifier: Apache-2.0

package identify

import (
	"encoding/binary"
	"errors"

	"github.com/tonylturner/containd/pkg/dp/ics/cip"
)

func enipEvidence(b []byte, udp bool) evidence {
	if len(b) < 2 {
		return pending(b)
	}
	command := le16(b)
	switch command {
	case 0:
		return evidence{state: Reject, end: min(len(b), 24), why: "NOP is not evidence"}
	case 4, 0x63, 0x64, 0x65, 0x66, 0x6f, 0x70, 0x72, 0x73:
	default:
		return invalid(b[:2])
	}
	if len(b) < 24 {
		if udp {
			return invalid(b)
		}
		return pending(b)
	}
	size := 24 + int(le16(b[2:]))
	// Match the shared reader's bounded stream profile.
	if size > 65536 || binary.LittleEndian.Uint32(b[20:24]) != 0 ||
		binary.LittleEndian.Uint32(b[8:12]) != 0 || udp && size != len(b) {
		return invalid(b[:24])
	}
	if len(b) < size {
		return pending(b)
	}
	h, err := cip.ParseEIPHeader(b[:size])
	if err != nil {
		return invalid(b[:size])
	}
	e := evidence{state: Candidate, end: size, why: "complete encapsulation"}
	switch command {
	case 0x65:
		if len(h.Data) != 4 || le16(h.Data) != 1 || le16(h.Data[2:]) != 0 {
			return invalid(b[:size])
		}
		e.role = Client
		if h.SessionHandle != 0 {
			e.role = Server
		}
		e.pair = func(other []byte) bool {
			g, err := cip.ParseEIPHeader(other)
			return err == nil && (!udp || 24+int(g.Length) == len(other)) &&
				g.Command == command && g.Options == 0 && g.Status == 0 &&
				g.SenderContext == h.SenderContext &&
				(g.SessionHandle == 0) != (h.SessionHandle == 0) &&
				len(g.Data) == 4 && le16(g.Data) == 1 && le16(g.Data[2:]) == 0
		}
	case 4, 0x63, 0x64:
		if h.SessionHandle != 0 {
			return invalid(b[:size])
		}
		if len(h.Data) == 0 {
			e.role = Client
		} else if validList(command, h.Data) {
			e.state, e.role, e.why = Confirmed, Server, "typed list reply"
		} else {
			return invalid(b[:size])
		}
	case 0x6f, 0x70:
		m, ok := validExplicit(h)
		if !ok {
			return invalid(b[:size])
		}
		e.role = Client
		if m.IsResponse {
			e.role = Server
		}
		e.pair = func(other []byte) bool {
			g, err := cip.ParseEIPHeader(other)
			if err != nil || udp && 24+int(g.Length) != len(other) ||
				g.Command != command || g.SessionHandle != h.SessionHandle ||
				g.Status != 0 || g.Options != 0 {
				return false
			}
			n, ok := validExplicit(g)
			return ok && m.IsResponse != n.IsResponse && m.ServiceCode == n.ServiceCode
		}
	}
	return e
}

func validExplicit(h *cip.EIPHeader) (*cip.CIPMessage, bool) {
	r := cip.ParseCIPMessage(h.Data)
	if r.CPF.Err != nil || r.MessageError != nil || r.Message == nil ||
		len(r.CPF.Conformance) != 0 || len(r.CPF.Undecoded) != 0 ||
		len(r.Message.Conformance) != 0 || len(r.CPF.Items) != 2 ||
		h.SessionHandle == 0 {
		return nil, false
	}
	want := uint16(0xb2)
	if h.Command == 0x70 {
		want = 0xb1
	}
	if r.CPF.Items[1].TypeID != want {
		return nil, false
	}
	if !r.Message.IsResponse {
		p := cip.ParseEPath(r.Message.Path)
		if len(p.Conformance) != 0 || len(p.Undecoded) != 0 || len(p.Raw) == 0 {
			return nil, false
		}
	}
	return r.Message, true
}

func validList(command uint16, data []byte) bool {
	// List command bodies start at the item count, unlike explicit bodies.
	// Adapt that offset to the exported CPF reader, not a second item walker.
	raw := make([]byte, 6+len(data))
	copy(raw[6:], data)
	r := cip.ParseCIPMessage(raw).CPF
	if !errors.Is(r.Err, cip.ErrNoCIPPayload) || len(r.Undecoded) != 0 {
		return false
	}
	if command == 0x64 {
		// The supported ListInterfaces reply has no defined interface items.
		return r.Count == 0
	}
	if r.Count == 0 {
		return false
	}
	for _, item := range r.Items {
		if !item.Complete {
			return false
		}
		switch command {
		case 4:
			if item.TypeID != 0x100 || len(item.Data) != 20 || le16(item.Data) != 1 {
				return false
			}
		case 0x63:
			if item.TypeID != 0xc || len(item.Data) < 34 || le16(item.Data) != 1 ||
				len(item.Data) != 34+int(item.Data[32]) {
				return false
			}
		}
	}
	return true
}
