// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package itdpi

import (
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

func FuzzDNSDecoderOnPacket(f *testing.F) {
	dec := NewDNSDecoder()
	udpState := flow.NewState(flow.Key{
		SrcIP:   dnsFlowState(12345, 53, 17).Key.SrcIP,
		DstIP:   dnsFlowState(12345, 53, 17).Key.DstIP,
		SrcPort: 12345,
		DstPort: 53,
		Proto:   17,
	}, time.Now())
	tcpState := flow.NewState(flow.Key{
		SrcIP:   udpState.Key.SrcIP,
		DstIP:   udpState.Key.DstIP,
		SrcPort: 12345,
		DstPort: 53,
		Proto:   6,
	}, time.Now())

	query := buildDNSQuery(0x1234, "example.com", 1)
	response := buildDNSResponse(0x1234, "example.com", 1)
	tcpQuery := append([]byte{0x00, byte(len(query))}, query...)

	f.Add(query, false)
	f.Add(response, false)
	f.Add(tcpQuery, true)
	f.Add([]byte{}, false)

	f.Fuzz(func(t *testing.T, data []byte, tcp bool) {
		pkt := &dpi.ParsedPacket{
			Payload: data,
			SrcPort: 12345,
			DstPort: 53,
		}
		state := udpState
		if tcp {
			pkt.Proto = "tcp"
			state = tcpState
		} else {
			pkt.Proto = "udp"
		}
		_, _ = dec.OnPacket(state, pkt)
		_, _, _ = parseQname(data, 0)
	})
}

func FuzzHTTPDecoderOnPacket(f *testing.F) {
	state := httpFlowState(12345, 80)

	f.Add([]byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	f.Add([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok"))
	f.Add([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
	f.Add([]byte("POST / HTTP/1.1\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\n\r\n"))
	f.Add([]byte("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"))
	f.Add([]byte("HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\nbodyHTTP/1.1 204 No Content\r\n\r\n"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseHTTP(data)
		fuzzITStream(data, NewHTTPDecoder(), state)
		fuzzHTTPReply(data)
		_, _ = NewHTTPDecoder().OnPacket(state, &dpi.ParsedPacket{
			Payload: data,
			Proto:   "tcp",
			SrcPort: 12345,
			DstPort: 80,
		})
	})
}

func FuzzTLSDecoderOnPacket(f *testing.F) {
	state := tlsFlowState(12345, 443)

	f.Add(buildClientHello("example.com", nil))
	f.Add(buildClientHello("secure.example.com", []string{"h2", "http/1.1"}))
	f.Add([]byte{0x16, 0x03, 0x01})
	f.Add([]byte{})
	f.Add(append(tlsRecord([]byte{11, 1, 0, 0}), tlsRecord([]byte{0})...))
	hello13 := helloWithExtensions([]byte{0, 43, 0, 5, 4, 3, 4, 3, 3})
	retry := append(append([]byte(nil), hello13...), 20, 3, 3, 0, 1, 1)
	f.Add(append(retry, hello13...))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = NewTLSDecoder().OnPacket(state, &dpi.ParsedPacket{
			Payload: data,
			Proto:   "tcp",
			SrcPort: 12345,
			DstPort: 443,
		})
		fuzzITStream(data, NewTLSDecoder(), state)
		if len(data) >= 5 && data[0] == 0x16 {
			recLen := int(data[3])<<8 | int(data[4])
			if recLen > len(data)-5 {
				recLen = len(data) - 5
			}
			if recLen > 4 {
				rec := data[5 : 5+recLen]
				hsLen := int(rec[1])<<16 | int(rec[2])<<8 | int(rec[3])
				if len(rec) >= 4 && hsLen > len(rec)-4 {
					hsLen = len(rec) - 4
				}
				if len(rec) >= 4 && hsLen >= 0 {
					_ = parseClientHello(rec[4 : 4+hsLen])
				}
			}
		}
	})
}

func FuzzSNMPDecoderOnPacket(f *testing.F) {
	dec := NewSNMPDecoder()
	state := snmpFlowState(32768, 161)

	f.Add(buildSNMPv2cPacket(1, "public", pduGetRequest, 1234, 0, 0, "1.3.6.1.2.1.1.1.0"))
	f.Add(buildSNMPv2cPacket(1, "private", pduSetRequest, 5678, 0, 0, "1.3.6.1.2.1.1.5.0"))
	f.Add(buildSNMPv1TrapPacket("public"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = dec.OnPacket(state, &dpi.ParsedPacket{
			Payload: data,
			Proto:   "udp",
			SrcPort: 32768,
			DstPort: 161,
		})
		_, _, _ = readBERLength(data, 0)
		_, _, _ = readBERInteger(data, 0)
		_, _, _ = readBEROID(data, 0)
	})
}

func FuzzSSHDecoderOnPacket(f *testing.F) {
	dec := NewSSHDecoder()
	state := sshFlowState(12345, 22)

	var kex []byte
	kexPayload := make([]byte, 0, 64)
	kexPayload = append(kexPayload, make([]byte, 16)...)
	kexPayload = appendNameList(kexPayload, "curve25519-sha256")
	kexPayload = appendNameList(kexPayload, "ssh-ed25519")
	kexPayload = appendNameList(kexPayload, "aes256-gcm@openssh.com")
	paddingLen := byte(4)
	pktLen := uint32(1 + 1 + len(kexPayload) + int(paddingLen))
	kex = append(kex, byte(pktLen>>24), byte(pktLen>>16), byte(pktLen>>8), byte(pktLen))
	kex = append(kex, paddingLen, 20)
	kex = append(kex, kexPayload...)
	kex = append(kex, make([]byte, paddingLen)...)

	f.Add([]byte("SSH-2.0-OpenSSH_8.9\r\n"))
	f.Add([]byte("SSH-1.99-OpenSSH_7.4\r\n"))
	f.Add(kex)
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = dec.OnPacket(state, &dpi.ParsedPacket{
			Payload: data,
			Proto:   "tcp",
			SrcPort: 12345,
			DstPort: 22,
		})
		_, _, _ = parseNameList(data, 0)
		_ = firstEntry(string(data))
	})
}

func FuzzSMBDecoderOnPacket(f *testing.F) {
	dec := NewSMBDecoder()
	state := smbFlowState(49152, 445)

	f.Add(buildSMBv2Packet(0x0000))
	f.Add(buildSMBv2Packet(0x0009))
	f.Add(buildSMBv1Packet(0x72))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = dec.OnPacket(state, &dpi.ParsedPacket{
			Payload: data,
			Proto:   "tcp",
			SrcPort: 49152,
			DstPort: 445,
		})
		if len(data) >= 8 {
			_ = dec.extractShareName(data)
		}
	})
}

func FuzzRDPDecoderOnPacket(f *testing.F) {
	dec := NewRDPDecoder()
	state := rdpFlowState(50000, 3389)

	cookie := []byte("Cookie: mstshash=testuser\r\n")
	f.Add(buildTPKT(buildX224CR(append(cookie, buildNegReq(0x03)...))))
	f.Add(buildTPKT(buildX224CC(buildNegResp(0x00))))
	f.Add(buildTPKT(buildX224CC(buildNegResp(0x02))))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = dec.OnPacket(state, &dpi.ParsedPacket{
			Payload: data,
			Proto:   "tcp",
			SrcPort: 50000,
			DstPort: 3389,
		})
		_ = extractCookie(data)
		_ = findNegReq(data)
		_, _ = decodeRequestedProtocols(uint32(len(data)))
		_, _ = decodeSelectedProtocol(uint32(len(data)))
	})
}

func FuzzNTPDecoderOnPacket(f *testing.F) {
	dec := NewNTPDecoder()
	state := ntpFlowState(50000, 123)

	f.Add(buildNTPPacket(0, 4, ntpModeClient, 0, [4]byte{}))
	f.Add(buildNTPPacket(0, 4, ntpModeServer, 1, [4]byte{'G', 'P', 'S', 0}))
	f.Add(buildNTPPacket(0, 4, ntpModeControl, 0, [4]byte{}))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = dec.OnPacket(state, &dpi.ParsedPacket{
			Payload: data,
			Proto:   "udp",
			SrcPort: 50000,
			DstPort: 123,
		})
		if len(data) >= 4 {
			_ = formatRefID(data[:4], uint8(len(data)))
		}
	})
}

// Exercise manager reassembly/lifecycle as well as packet-local parsing. Each
// input gets its own compression/encryption state, independent of fuzz order.
func fuzzITStream(data []byte, decoder dpi.Decoder, state *flow.State) {
	mgr := dpi.NewManager(decoder)
	split := len(data) / 2
	for _, legacy := range []bool{false, true} {
		for i, p := range [][]byte{data[:split], data[split:]} {
			off := int64(0)
			if i == 1 {
				off = int64(split)
			}
			pkt := &dpi.ParsedPacket{Payload: p, Proto: "tcp", HasOffset: !legacy, Session: "fuzz", Dir: dpi.ClientToServer, Offset: off, TCPSeqValid: legacy, TCPSeq: uint32(100 + off)}
			if legacy {
				pkt.Dir = dpi.DirUnknown
				pkt.Session = ""
			}
			mgr.Inspect(state, pkt)
		}
		if legacy {
			_, _ = mgr.OnFlowEnd(state)
		} else {
			mgr.EndStream("fuzz")
		}
	}
}
