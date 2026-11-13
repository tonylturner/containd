// SPDX-License-Identifier: Apache-2.0

package itdpi

import (
	"bytes"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

func FuzzHTTPPacketBoundaryRecovery(f *testing.F) {
	for _, seed := range [][]byte{
		{}, []byte("x"), []byte("G"), []byte("garbage\r\n\r\n"),
		[]byte("GET /incomplete HTTP/1.1\r\nHost: unfinished"),
		[]byte("HTTP/1.1 200 OK\r\n\r\nbody"),
		[]byte("HTTP/1.1 404 "),
		[]byte("GET /wrong-endpoint HTTP/1.1\r\n\r\n"),
		bytes.Repeat([]byte{0xee}, 65536),
	} {
		f.Add(seed, uint8(13))
	}
	f.Fuzz(func(t *testing.T, data []byte, width uint8) {
		if len(data) > 4096 {
			data = data[:4096]
		}
		// Construct hostile HTTP/1 bytes without a body declaration or an
		// HTTP/2 preface. Declared bodies and HTTP/2 have separate invariants.
		data = bytes.ReplaceAll(data, []byte{':'}, []byte{'_'})
		data = bytes.ReplaceAll(data, []byte{0}, []byte{0xee})
		data = bytes.ReplaceAll(data, []byte("PRI * HTTP/2.0"), []byte("invalid preface"))
		for _, known := range []bool{false, true} {
			mgr := dpi.NewManager(NewHTTPDecoder())
			client, server := httpFlowState(12345, 80), httpFlowState(80, 12345)
			server.Key.SrcIP, server.Key.DstIP = client.Key.DstIP, client.Key.SrcIP
			seq := [2]uint32{1000, 2000}
			var events [2][]dpi.Event
			send := func(i int, p []byte) {
				st, role := client, dpi.ClientToServer
				if i == 1 {
					st, role = server, dpi.ServerToClient
				}
				if !known {
					role = dpi.DirUnknown
				}
				r := mgr.Inspect(st, &dpi.ParsedPacket{Proto: "tcp", Payload: p, TCPSeqValid: true, TCPSeq: seq[i], Role: role})
				seq[i] += uint32(len(p))
				if r.Err != nil {
					t.Fatal(r.Err)
				}
				events[i] = append(events[i], r.Events...)
			}
			order := [2]int{0, 1}
			if width&1 != 0 {
				order = [2]int{1, 0}
			}
			for _, i := range order {
				for p := data; len(p) > 0; {
					n := min(len(p), int(width)+1)
					send(i, p[:n])
					p = p[n:]
				}
			}
			beforePair := [2]int{len(events[0]), len(events[1])}
			send(0, []byte("GET /genuine HTTP/1.1\r\n\r\n"))
			send(1, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Type: application/genuine\r\n\r\n"))
			found := [2]bool{}
			for i, all := range events {
				for _, ev := range all[beforePair[i]:] {
					found[i] = found[i] || i == 0 && ev.Kind == "request" && ev.Attributes["method"] == "GET" && ev.Attributes["path"] == "/genuine" ||
						i == 1 && ev.Kind == "response" && ev.Attributes["status"] == "200" && ev.Attributes["content_type"] == "application/genuine"
				}
			}
			if !found[0] || !found[1] {
				t.Fatalf("packet-boundary pair lost: %v", events)
			}
			for i := 0; i < 2; i++ {
				send(i, []byte("not HTTP\r\n\r\n"))
				before := len(events[i])
				for j := 0; j < 100; j++ {
					send(i, []byte("not HTTP\r\n\r\n"))
				}
				if len(events[i]) != before {
					t.Fatal("unanchored bytes caused an event flood")
				}
				headers, malformed := 0, 0
				for _, ev := range events[i] {
					if ev.Kind == "malformed" {
						malformed++
					} else {
						headers++
					}
				}
				if malformed > headers+1 {
					t.Fatalf("malformed bound exceeded: %d errors / %d anchors", malformed, headers)
				}
			}
		}
	})
}
