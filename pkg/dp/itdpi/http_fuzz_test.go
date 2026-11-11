// SPDX-License-Identifier: Apache-2.0

package itdpi

import (
	"strings"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

func fuzzHTTPReply(data []byte) {
	for _, requests := range []string{
		"HEAD / HTTP/1.1\r\n\r\nGET /next HTTP/1.1\r\n\r\n",
		"CONNECT example.test:443 HTTP/1.1\r\n\r\n",
		"GET /ws HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
		strings.Repeat("HEAD / HTTP/1.1\r\n\r\n", maxHTTPRequestMethods+1),
	} {
		fuzzHTTPCorrelated(data, []byte(requests))
	}
}

func fuzzHTTPCorrelated(data, requests []byte) {
	d := NewHTTPDecoder()
	mgr := dpi.NewManager(d)
	client := httpFlowState(12345, 80)
	server := httpFlowState(80, 12345)
	server.Key.SrcIP, server.Key.DstIP = client.Key.DstIP, client.Key.SrcIP
	mgr.Inspect(client, &dpi.ParsedPacket{Proto: "tcp", Payload: requests, TCPSeqValid: true, TCPSeq: 100})
	// Hostile client response text must not steal correlation or blind peers.
	mgr.Inspect(client, &dpi.ParsedPacket{Proto: "tcp", Payload: data, TCPSeqValid: true, TCPSeq: 100 + uint32(len(requests))})
	split := len(data) / 2
	for i, p := range [][]byte{data[:split], data[split:]} {
		seq := uint32(200)
		if i == 1 {
			seq += uint32(split)
		}
		mgr.Inspect(server, &dpi.ParsedPacket{Proto: "tcp", Payload: p, TCPSeqValid: true, TCPSeq: seq})
	}
	for _, c := range d.connections {
		if len(c.methods) > maxHTTPRequestMethods {
			panic("unbounded HTTP request correlation")
		}
	}
	_, _ = mgr.OnFlowEnd(client)
	_, _ = mgr.OnFlowEnd(server)
	if len(d.streams) != 0 || len(d.connections) != 0 {
		panic("HTTP stream state leaked")
	}
}
