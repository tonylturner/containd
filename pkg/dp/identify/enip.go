// SPDX-License-Identifier: Apache-2.0

package identify

import (
	"encoding/binary"
	"errors"

	"github.com/tonylturner/containd/pkg/dp/ics/cip"
)

type enipMessage struct {
	header  *cip.EIPHeader
	role    Role
	service uint8
}

func enipEvidence(b []byte, udp bool) evidence {
	e := pending(b)
	for offset := 0; offset < len(b); {
		h, size, err := readEncapsulation(b[offset:], udp)
		if err != nil {
			return invalid(b)
		}
		if size == 0 {
			break
		}
		if h.Command == 0 {
			e.neutral = true
			offset += size
			continue
		}
		m, state := enipFrame(h)
		if state == Reject {
			return invalid(b)
		}
		if strength(state) > strength(e.state) {
			e.state, e.why = state, "complete encapsulation"
		}
		if len(e.enip) == 0 {
			e.role = m.role
		} else if e.role != m.role {
			e.role = Unknown
		}
		e.enip = append(e.enip, m)
		offset += size
	}
	if len(e.enip) == 0 && e.neutral {
		e.why = "NOP is neutral"
	}
	return e
}

// Header checks also apply to partial frames so a known bad boundary rejects
// without waiting for the advertised body. The shared reader owns decoding.
func readEncapsulation(b []byte, udp bool) (*cip.EIPHeader, int, error) {
	if len(b) < 2 {
		return nil, 0, nil
	}
	command := le16(b)
	switch command {
	case 0, 4, 0x63, 0x64, 0x65, 0x66, 0x6f, 0x70, 0x72, 0x73:
	default:
		return nil, 0, cip.ErrInvalidCPF
	}
	if udp && command != 0 && command != 4 && command != 0x63 && command != 0x64 {
		return nil, 0, cip.ErrInvalidCPF
	}
	if len(b) < 24 {
		return nil, 0, nil
	}
	size := 24 + int(le16(b[2:]))
	status := binary.LittleEndian.Uint32(b[8:12])
	if size > 65536 || binary.LittleEndian.Uint32(b[20:24]) != 0 || !knownStatus(status) ||
		command == 0 && status != 0 || udp && size != len(b) {
		return nil, 0, cip.ErrInvalidCPF
	}
	if len(b) < size {
		return nil, 0, nil
	}
	h, err := cip.ParseEIPHeader(b[:size])
	return h, size, err
}

func knownStatus(status uint32) bool {
	switch status {
	case 0, 1, 2, 3, 0x64, 0x65, 0x69:
		return true
	default:
		return false
	}
}

func enipFrame(h *cip.EIPHeader) (enipMessage, State) {
	m := enipMessage{header: h, role: Unknown}
	if h.Status != 0 {
		// Error encapsulations may have no command payload. They identify no
		// request by themselves; a validated request must correlate them.
		m.role = Server
		return m, Candidate
	}
	switch h.Command {
	case 0x65:
		if len(h.Data) != 4 || le16(h.Data) != 1 || le16(h.Data[2:]) != 0 {
			return m, Reject
		}
		m.role = Client
		if h.SessionHandle != 0 {
			m.role = Server
		}
	case 4, 0x63, 0x64:
		if h.SessionHandle != 0 {
			return m, Reject
		}
		if len(h.Data) == 0 {
			m.role = Client
		} else {
			m.role = Server
			return m, listEvidence(h.Command, h.Data)
		}
	case 0x6f, 0x70:
		msg, ok := validExplicit(h)
		if !ok {
			return m, Reject
		}
		m.role, m.service = Client, msg.ServiceCode
		if msg.IsResponse {
			m.role = Server
		}
	}
	return m, Candidate
}

func enipPair(request, reply enipMessage) bool {
	a, b := request.header, reply.header
	if request.role != Client || reply.role != Server || a.Status != 0 || a.Command != b.Command {
		return false
	}
	if b.Status != 0 {
		return a.SenderContext == b.SenderContext &&
			(a.Command == 0x65 && a.SessionHandle == 0 || a.SessionHandle == b.SessionHandle)
	}
	switch a.Command {
	case 0x65:
		return a.SessionHandle == 0 && b.SessionHandle != 0 && a.SenderContext == b.SenderContext
	case 0x6f, 0x70:
		return a.SessionHandle == b.SessionHandle && request.service == reply.service
	}
	return false
}

func validExplicit(h *cip.EIPHeader) (*cip.CIPMessage, bool) {
	r := cip.ParseCIPMessage(h.Data)
	if r.CPF.Err != nil || r.MessageError != nil || r.Message == nil ||
		len(r.CPF.Conformance) != 0 || len(r.CPF.Undecoded) != 0 ||
		len(r.Message.Conformance) != 0 || r.CPF.Selected < 1 ||
		h.SessionHandle == 0 {
		return nil, false
	}
	want := uint16(0xb2)
	if h.Command == 0x70 {
		want = 0xb1
	}
	if r.CPF.Items[r.CPF.Selected].TypeID != want {
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

func listEvidence(command uint16, data []byte) State {
	// List command bodies start at the item count, unlike explicit bodies.
	// Adapt that offset to the exported CPF reader, not a second item walker.
	raw := make([]byte, 6+len(data))
	copy(raw[6:], data)
	r := cip.ParseCIPMessage(raw).CPF
	if !errors.Is(r.Err, cip.ErrNoCIPPayload) || len(r.Undecoded) != 0 {
		return Reject
	}
	if r.Count == 0 {
		if command == 0x63 || command == 0x64 {
			return Candidate
		}
		return Reject
	}
	if command == 0x64 {
		return Reject
	} // no defined nonempty interface items in this profile
	for _, item := range r.Items {
		if !item.Complete {
			return Reject
		}
		switch command {
		case 4:
			if item.TypeID != 0x100 || len(item.Data) != 20 || le16(item.Data) != 1 {
				return Reject
			}
		case 0x63:
			if item.TypeID != 0xc || len(item.Data) < 34 || le16(item.Data) != 1 ||
				len(item.Data) != 34+int(item.Data[32]) {
				return Reject
			}
		}
	}
	return Confirmed
}
