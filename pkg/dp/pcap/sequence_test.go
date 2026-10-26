// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package pcap

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

// recordFramer frames 4-byte records on TCP port 9999.
type recordFramer struct{}

func (recordFramer) Supports(s *flow.State) bool {
	return s != nil && s.Key.Proto == 6 && (s.Key.SrcPort == 9999 || s.Key.DstPort == 9999)
}
func (recordFramer) Ports() ([]uint16, []uint16) { return []uint16{9999}, nil }
func (recordFramer) OnPacket(*flow.State, *dpi.ParsedPacket) ([]dpi.Event, error) {
	return nil, nil
}
func (recordFramer) OnFlowEnd(*flow.State) ([]dpi.Event, error) { return nil, nil }
func (recordFramer) Protocol() string                           { return "rec" }
func (recordFramer) ParseStream(_ *flow.State, v dpi.StreamView) (dpi.StreamResult, error) {
	var res dpi.StreamResult
	for off := 0; off+4 <= len(v.Bytes); off += 4 {
		start := v.Base + int64(off)
		if string(v.Bytes[off:off+4]) == "BAD!" {
			return res, &dpi.FrameError{Offset: start, Reason: "bad", Event: dpi.Event{Proto: "rec", Kind: "malformed"}}
		}
		res.Frames = append(res.Frames, dpi.DecodedFrame{Start: start, End: start + 4, Events: []dpi.Event{{
			Proto: "rec", Kind: "record", Attributes: map[string]any{"rec": string(v.Bytes[off : off+4])},
		}}})
		res.Consumed = off + 4
	}
	res.NeedMore = len(v.Bytes)%4 != 0
	return res, nil
}

// tcpFrame builds an Ethernet/IPv4/TCP frame 10.0.0.1:40000 -> 10.0.0.2:9999.
func tcpFrame(seq uint32, flags byte, payload string) []byte {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], 40000)
	binary.BigEndian.PutUint16(tcp[2:], 9999)
	binary.BigEndian.PutUint32(tcp[4:], seq)
	tcp[12] = 5 << 4
	tcp[13] = flags
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(40+len(payload)))
	ip[9] = 6
	copy(ip[12:16], []byte{10, 0, 0, 1})
	copy(ip[16:20], []byte{10, 0, 0, 2})
	eth := make([]byte, 14)
	binary.BigEndian.PutUint16(eth[12:], 0x0800)
	frame := append(eth, ip...)
	frame = append(frame, tcp...)
	return append(frame, payload...)
}

func analysisRecords(res *AnalysisResult) (recs []string, malformed int) {
	for _, ev := range res.Events {
		switch ev.Kind {
		case "record":
			recs = append(recs, ev.Attributes["rec"].(string))
		case "malformed":
			malformed++
		}
	}
	return recs, malformed
}

// TestAnalyzeUsesTCPSequence pins offline parity with the live engine
// (contracts K8): every message is parsed once, retransmissions are not
// parsed again, and events before a stream error are kept.
func TestAnalyzeUsesTCPSequence(t *testing.T) {
	const ack, psh = 0x10, 0x08
	data := buildPCAP([][]byte{
		tcpFrame(0, ack|psh, "AAAA"),
		tcpFrame(4, ack|psh, "BBBB"),
		tcpFrame(0, ack|psh, "AAAA"),
		tcpFrame(8, ack|psh, "CC"),
	})
	res, err := Analyze(bytes.NewReader(data), recordFramer{})
	if err != nil {
		t.Fatal(err)
	}
	recs, malformed := analysisRecords(res)
	if len(recs) != 2 || recs[0] != "AAAA" || recs[1] != "BBBB" {
		t.Fatalf("records = %v, want [AAAA BBBB]", recs)
	}
	if malformed != 0 {
		t.Fatalf("malformed = %d", malformed)
	}
	data = buildPCAP([][]byte{tcpFrame(0, ack|psh, "GOODBAD!")})
	res, err = Analyze(bytes.NewReader(data), recordFramer{})
	if err != nil {
		t.Fatal(err)
	}
	if recs, malformed = analysisRecords(res); len(recs) != 1 || malformed != 1 {
		t.Fatalf("records=%v malformed=%d, want the frame before the error and its malformed event", recs, malformed)
	}
}

// iecFramer emits one iec104 event per 4-byte record on port 2404.
type iecFramer struct{ recordFramer }

func (iecFramer) Supports(s *flow.State) bool {
	return s != nil && s.Key.Proto == 6 && (s.Key.SrcPort == 2404 || s.Key.DstPort == 2404)
}
func (iecFramer) Ports() ([]uint16, []uint16) { return []uint16{2404}, nil }
func (iecFramer) Protocol() string            { return "iec104" }
func (iecFramer) ParseStream(_ *flow.State, v dpi.StreamView) (dpi.StreamResult, error) {
	var res dpi.StreamResult
	for off := 0; off+4 <= len(v.Bytes); off += 4 {
		start := v.Base + int64(off)
		res.Frames = append(res.Frames, dpi.DecodedFrame{Start: start, End: start + 4, Events: []dpi.Event{{
			Proto: "iec104", Kind: "request", Attributes: map[string]any{"type_id": uint8(46), "is_write": true},
		}}})
		res.Consumed = off + 4
	}
	return res, nil
}

// iecFrame builds an Ethernet/IPv4/TCP frame between 10.0.0.1:40000 (the
// client) and 10.0.0.2:2404.
func iecFrame(fromClient bool, seq, ack uint32, flags byte, payload string) []byte {
	f := tcpFrame(seq, flags, payload)
	tcp := f[34:]
	binary.BigEndian.PutUint32(tcp[8:], ack)
	if fromClient {
		binary.BigEndian.PutUint16(tcp[0:], 40000)
		binary.BigEndian.PutUint16(tcp[2:], 2404)
	} else {
		binary.BigEndian.PutUint16(tcp[0:], 2404)
		binary.BigEndian.PutUint16(tcp[2:], 40000)
		copy(f[26:30], []byte{10, 0, 0, 2})
		copy(f[30:34], []byte{10, 0, 0, 1})
	}
	return f
}

func TestAnalyzeTracksIEC104SessionsAndNeverLearnsThem(t *testing.T) {
	const syn, ack, psh = 0x02, 0x10, 0x08
	frames := [][]byte{
		iecFrame(true, 99, 0, syn, ""),
		iecFrame(false, 499, 100, syn|ack, ""),
		iecFrame(true, 100, 500, ack|psh, "CMD1"),
		iecFrame(true, 100, 500, ack|psh, "CMD1"), // retransmission
		iecFrame(true, 104, 500, ack|psh, "CMD2"),
	}
	// A second connection whose SYN was not captured is never parsed.
	mid := iecFrame(true, 7000, 9000, ack|psh, "LOST")
	binary.BigEndian.PutUint16(mid[34:], 40001)
	frames = append(frames, mid)
	res, err := AnalyzeForPolicy(bytes.NewReader(buildPCAP(frames)), iecFramer{})
	if err != nil {
		t.Fatal(err)
	}
	if res.EventSummary["iec104"] != 2 {
		t.Fatalf("iec104 events = %d, want 2 (once each, none mid-stream)", res.EventSummary["iec104"])
	}
	if len(res.Rules) != 0 || len(res.Profiles) != 0 {
		t.Fatalf("PCAP-to-policy learned IEC104: rules=%+v profiles=%+v", res.Rules, res.Profiles)
	}
}
