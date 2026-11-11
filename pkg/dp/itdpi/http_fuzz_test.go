// SPDX-License-Identifier: Apache-2.0

package itdpi

import "github.com/tonylturner/containd/pkg/dp/dpi"

func fuzzHTTPReply(data []byte) {
	mgr := dpi.NewManager(NewHTTPDecoder())
	client := httpFlowState(12345, 80)
	server := httpFlowState(80, 12345)
	server.Key.SrcIP, server.Key.DstIP = client.Key.DstIP, client.Key.SrcIP
	mgr.Inspect(client, &dpi.ParsedPacket{Proto: "tcp", Payload: []byte("HEAD / HTTP/1.1\r\n\r\nGET /next HTTP/1.1\r\n\r\n"), TCPSeqValid: true, TCPSeq: 100})
	split := len(data) / 2
	for i, p := range [][]byte{data[:split], data[split:]} {
		seq := uint32(200)
		if i == 1 {
			seq += uint32(split)
		}
		mgr.Inspect(server, &dpi.ParsedPacket{Proto: "tcp", Payload: p, TCPSeqValid: true, TCPSeq: seq})
	}
	_, _ = mgr.OnFlowEnd(client)
	_, _ = mgr.OnFlowEnd(server)
}
