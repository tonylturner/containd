// SPDX-License-Identifier: Apache-2.0
package itdpi_test

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/itdpi"
)

type recoveryEvent struct {
	kind, path, content string
	reply               bool
}
type recoveryHarness struct {
	send   func(bool, string)
	events func() []recoveryEvent
}

func recoveryNew(t *testing.T, mode string) recoveryHarness {
	seq := [2]uint32{1000, 2000}
	src, dst := net.IPv4(10, 10, 2, 1).To4(), net.IPv4(10, 10, 2, 2).To4()
	states := [2]*flow.State{flow.NewState(flow.Key{SrcIP: src, DstIP: dst, SrcPort: 40000, DstPort: 80, Proto: 6}, time.Now()), flow.NewState(flow.Key{SrcIP: dst, DstIP: src, SrcPort: 80, DstPort: 40000, Proto: 6}, time.Now())}
	var e *metadataEngine
	var mgr *dpi.Manager
	var all []recoveryEvent
	if mode == "engine" {
		e = newMetadataEngine(t, 80)
	} else {
		mgr = dpi.NewManager(itdpi.NewHTTPDecoder())
	}
	return recoveryHarness{send: func(reply bool, raw string) {
		i := 0
		if reply {
			i = 1
		}
		st := states[i]
		p := []byte(raw)
		if e != nil {
			e.send(t, reply, p)
		} else {
			r := mgr.Inspect(st, &dpi.ParsedPacket{Proto: "tcp", Payload: p, SrcPort: st.Key.SrcPort, DstPort: st.Key.DstPort, TCPSeqValid: true, TCPSeq: seq[i]})
			if r.Err != nil {
				t.Fatal(r.Err)
			}
			for _, ev := range r.Events {
				all = append(all, recoveryEvent{ev.Kind, fmt.Sprint(ev.Attributes["path"]), fmt.Sprint(ev.Attributes["content_type"]), reply})
			}
		}
		seq[i] += uint32(len(p))
	}, events: func() []recoveryEvent {
		if e == nil {
			return all
		}
		var out []recoveryEvent
		for _, ev := range e.e.Events().List(100000) {
			out = append(out, recoveryEvent{ev.Kind, fmt.Sprint(ev.Attributes["path"]), fmt.Sprint(ev.Attributes["content_type"]), fmt.Sprint(ev.Attributes["src_port"]) == "80"})
		}
		return out
	}}
}
func recoveryModes(t *testing.T, fn func(*testing.T, string)) {
	for _, mode := range []string{"manager", "engine"} {
		t.Run(mode, func(t *testing.T) { fn(t, mode) })
	}
}
func recoveryPath(h recoveryHarness, path string) bool {
	for _, ev := range h.events() {
		if ev.kind == "request" && ev.path == path && !ev.reply {
			return true
		}
	}
	return false
}
func recoveryContent(h recoveryHarness, content string) bool {
	for _, ev := range h.events() {
		if ev.kind == "response" && ev.content == content && ev.reply {
			return true
		}
	}
	return false
}
func recoveryCount(h recoveryHarness, kind string) int {
	n := 0
	for _, ev := range h.events() {
		if ev.kind == kind {
			n++
		}
	}
	return n
}
func recoveryReply(content string) string {
	return "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Type: " + content + "\r\n\r\n"
}
func recoveryByteSend(h recoveryHarness, reply bool, raw string) {
	for _, b := range []byte(raw) {
		h.send(reply, string([]byte{b}))
	}
}
func recoveryCheck(t *testing.T, h recoveryHarness, path, content string) {
	t.Helper()
	if !recoveryPath(h, path) || !recoveryContent(h, content) {
		events := h.events()
		t.Errorf("missing real request=%s (%v) or real server response=%s (%v); requests=%d responses=%d malformed=%d; last events=%v", path, recoveryPath(h, path), content, recoveryContent(h, content), recoveryCount(h, "request"), recoveryCount(h, "response"), recoveryCount(h, "malformed"), events[max(0, len(events)-8):])
	}
}

func TestHTTPRecoveryOverflowRecovery(t *testing.T) {
	recoveryModes(t, func(t *testing.T, mode string) {
		for _, n := range []int{65, 128, 1000} {
			t.Run(fmt.Sprint(n), func(t *testing.T) {
				h := recoveryNew(t, mode)
				for i := 0; i < n; i++ {
					h.send(false, fmt.Sprintf("GET /queued/%d HTTP/1.1\r\n\r\n", i))
				}
				for i := 0; i < n; i++ {
					h.send(true, recoveryReply("application/queued"))
				}
				h.send(false, "HEAD /head HTTP/1.1\r\n\r\nGET /after HTTP/1.1\r\n\r\n")
				recoveryByteSend(h, true, "HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\nContent-Type: application/head\r\n\r\n"+recoveryReply("application/after"))
				recoveryCheck(t, h, "/after", "application/after")
				if recoveryCount(h, "malformed") != 0 || recoveryCount(h, "request") != n+2 || recoveryCount(h, "response") != n+2 {
					t.Error("incorrect queue recovery counts")
				}
				t.Logf("%d requests/replies drained; subsequent HEAD/GET inspected", n)
			})
		}
	})
}
func TestHTTPRecoveryForgedClientResponses(t *testing.T) {
	recoveryModes(t, func(t *testing.T, mode string) {
		for _, prior := range []bool{false, true} {
			t.Run(fmt.Sprint(prior), func(t *testing.T) {
				h := recoveryNew(t, mode)
				if prior {
					h.send(false, "HEAD /head HTTP/1.1\r\n\r\n")
				}
				recoveryByteSend(h, false, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
				if prior {
					recoveryByteSend(h, false, "HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n")
				}
				h.send(false, "GET /after HTTP/1.1\r\n\r\n")
				if prior {
					h.send(true, "HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\nContent-Type: application/head\r\n\r\n")
				}
				h.send(true, recoveryReply("application/after"))
				recoveryCheck(t, h, "/after", "application/after")
				if prior && !recoveryContent(h, "application/head") {
					t.Error("missing genuine server HEAD marker")
				}
				t.Logf("real peer markers preserved; forged response counts deliberately not asserted")
			})
		}
	})
}
func TestHTTPRecoveryUnansweredCONNECT(t *testing.T) {
	recoveryModes(t, func(t *testing.T, mode string) {
		h := recoveryNew(t, mode)
		h.send(false, "CONNECT example.test:443 HTTP/1.1\r\n\r\n")
		h.send(false, "HTTP/1.1 200 Connection Established\r\n\r\n")
		for i := 0; i < 100; i++ {
			h.send(false, fmt.Sprintf("GET /later/%d HTTP/1.1\r\n\r\n", i))
		}
		if !recoveryPath(h, "/later/99") || recoveryCount(h, "request") != 101 {
			t.Fatal(h.events())
		}
		t.Log("101 requests remain visible without server response")
	})
}
func TestHTTPRecoveryTunnelMatching(t *testing.T) {
	recoveryModes(t, func(t *testing.T, mode string) {
		for _, connect := range []bool{false, true} {
			t.Run(fmt.Sprint(connect), func(t *testing.T) {
				h := recoveryNew(t, mode)
				req := "GET /upgrade HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: custom/V1, WebSocket\r\n\r\n"
				rep := "HTTP/1.1 101 Switching Protocols\r\nConnection: keep-alive, Upgrade\r\nUpgrade: custom/V1, websocket\r\n\r\n"
				if connect {
					req = "CONNECT example.test:443 HTTP/1.1\r\n\r\n"
					rep = "HTTP/1.1 200 Connection Established\r\n\r\n"
				}
				h.send(false, "GET /first HTTP/1.1\r\n\r\n"+req)
				h.send(true, recoveryReply("application/first"))
				h.send(false, "GET /before HTTP/1.1\r\n\r\n")
				if !recoveryPath(h, "/before") {
					t.Fatal("earlier 200 opened tunnel")
				}
				h.send(true, rep)
				h.send(false, "GET /inside HTTP/1.1\r\n\r\n")
				if !recoveryPath(h, "/inside") {
					t.Fatal("packet-boundary request did not re-anchor tunnel")
				}
				t.Log("only matching server response opened tunnel")
			})
		}
	})
}
func TestHTTPRecoveryInvalidUpgradeLayers(t *testing.T) {
	recoveryModes(t, func(t *testing.T, mode string) {
		for _, selected := range []string{"WebSocket, unoffered", "custom/v1", "WebSocket,", "web socket", "/V1", "custom/", ""} {
			t.Run(selected, func(t *testing.T) {
				h := recoveryNew(t, mode)
				h.send(false, "GET /upgrade HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: custom/V1, websocket\r\n\r\n")
				h.send(true, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: "+selected+"\r\n\r\n")
				h.send(false, "GET /after HTTP/1.1\r\n\r\n")
				h.send(true, recoveryReply("application/after"))
				recoveryCheck(t, h, "/after", "application/after")
			})
		}
	})
}
func TestHTTPRecoveryServerRequestLinesKnownRole(t *testing.T) {
	recoveryModes(t, func(t *testing.T, mode string) {
		h := recoveryNew(t, mode)
		h.send(false, "HEAD /head HTTP/1.1\r\n\r\nGET /after HTTP/1.1\r\n\r\n")
		h.send(true, "GET /wrong-side HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nContent-Length: 18446744073709551615\r\n\r\n")
		recoveryByteSend(h, true, "HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n"+recoveryReply("application/after"))
		recoveryCheck(t, h, "/after", "application/after")
		t.Log("known-role wrong-side request did not frame body or steal correlation")
	})
}
func TestHTTPRecoveryReplyFirst(t *testing.T) {
	recoveryModes(t, func(t *testing.T, mode string) {
		h := recoveryNew(t, mode)
		h.send(true, recoveryReply("application/pickup"))
		h.send(false, "HEAD /head HTTP/1.1\r\n\r\nGET /after HTTP/1.1\r\n\r\n")
		h.send(true, "HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n"+recoveryReply("application/after"))
		recoveryCheck(t, h, "/after", "application/after")
	})
}
func TestHTTPRecoveryReplyFirstRolePoison(t *testing.T) {
	recoveryModes(t, func(t *testing.T, mode string) {
		h := recoveryNew(t, mode)
		h.send(true, recoveryReply("application/pickup"))
		h.send(true, "GET /server-forged HTTP/1.1\r\n\r\n")
		h.send(false, "GET /after HTTP/1.1\r\n\r\n")
		h.send(true, recoveryReply("application/after"))
		recoveryCheck(t, h, "/after", "application/after")
	})
}

func TestHTTPRecoveryRequestFirstRolePoison(t *testing.T) {
	recoveryModes(t, func(t *testing.T, mode string) {
		h := recoveryNew(t, mode)
		h.send(true, "GET /server-forged HTTP/1.1\r\n\r\n")
		h.send(false, "GET /after HTTP/1.1\r\n\r\n")
		h.send(true, recoveryReply("application/after"))
		recoveryCheck(t, h, "/after", "application/after")
	})
}

func TestHTTPRecoveryRoleRevisionCannotTrustBodyCorrelation(t *testing.T) {
	recoveryModes(t, func(t *testing.T, mode string) {
		h := recoveryNew(t, mode)
		h.send(false, "HEAD /head HTTP/1.1\r\n\r\n")
		h.send(true, "GET /server-forged HTTP/1.1\r\n\r\n")
		h.send(false, "GET /after HTTP/1.1\r\n\r\n")
		h.send(true, "HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\nContent-Type: application/head\r\n\r\n")
		h.send(true, recoveryReply("application/after"))
		recoveryCheck(t, h, "/after", "application/after")
		if !recoveryContent(h, "application/head") {
			t.Fatal("role revision lost the actual HEAD reply")
		}
	})
}
func TestHTTPRecoveryInterleavedPipeline(t *testing.T) {
	recoveryModes(t, func(t *testing.T, mode string) {
		h := recoveryNew(t, mode)
		for i := 0; i < 65; i++ {
			h.send(false, "GET /queued HTTP/1.1\r\n\r\n")
		}
		for i := 0; i < 30; i++ {
			h.send(true, recoveryReply("application/queued"))
			h.send(false, "GET /more HTTP/1.1\r\n\r\n")
		}
		for i := 0; i < 65; i++ {
			h.send(true, recoveryReply("application/drained"))
		}
		h.send(false, "HEAD /head HTTP/1.1\r\n\r\nGET /after HTTP/1.1\r\n\r\n")
		h.send(true, "HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n"+recoveryReply("application/after"))
		recoveryCheck(t, h, "/after", "application/after")
	})
}
func TestHTTPRecoveryOverflowBodyFalseTunnel(t *testing.T) {
	recoveryModes(t, func(t *testing.T, mode string) {
		for _, connect := range []bool{false, true} {
			t.Run(fmt.Sprint(connect), func(t *testing.T) {
				h := recoveryNew(t, mode)
				for i := 0; i < 65; i++ {
					h.send(false, "GET /queued HTTP/1.1\r\n\r\n")
				}
				fakeFinal := strings.Repeat("HTTP/1.1 204 No Content\r\n\r\n", 64)
				fakeSwitch := "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
				upgradeReq := "GET /upgrade HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
				if connect {
					fakeSwitch = "HTTP/1.1 200 Connection Established\r\n\r\n"
					upgradeReq = "CONNECT example.test:443 HTTP/1.1\r\n\r\n"
				}
				body := fakeFinal + fakeSwitch
				// This is a real first GET response. Every apparent extra response is inside its Content-Length body.
				first := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", len(body)) + fakeFinal
				if connect {
					h.send(true, first)
				} else {
					recoveryByteSend(h, true, first)
				}
				h.send(false, upgradeReq)
				if connect {
					h.send(true, fakeSwitch)
				} else {
					recoveryByteSend(h, true, fakeSwitch)
				}
				for i := 0; i < 64; i++ {
					h.send(true, recoveryReply("application/remaining"))
				}
				h.send(true, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nContent-Type: application/upgrade-denied\r\n\r\n")
				h.send(false, "GET /after HTTP/1.1\r\n\r\n")
				h.send(true, recoveryReply("application/after"))
				recoveryCheck(t, h, "/after", "application/after")
				if recoveryCount(h, "response") != 67 || recoveryCount(h, "malformed") != 0 {
					t.Fatal("body text changed response correlation", h.events())
				}
				t.Logf("requests=%d responses=%d malformed=%d", recoveryCount(h, "request"), recoveryCount(h, "response"), recoveryCount(h, "malformed"))
			})
		}
	})
}

func TestHTTPRecoveryDuplicateUpgradeFields(t *testing.T) {
	recoveryModes(t, func(t *testing.T, mode string) {
		for _, first := range []string{"unoffered", "custom/v1"} {
			t.Run(first, func(t *testing.T) {
				h := recoveryNew(t, mode)
				h.send(false, "GET /upgrade HTTP/1.1\r\nConnection: Upgrade\r\nUpgrade: custom/V1, websocket\r\n\r\n")
				h.send(true, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: "+first+"\r\nUpgrade: websocket\r\n\r\n")
				h.send(false, "GET /after HTTP/1.1\r\n\r\n")
				h.send(true, recoveryReply("application/after"))
				recoveryCheck(t, h, "/after", "application/after")
			})
		}
	})
}
