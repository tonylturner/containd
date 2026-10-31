// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package pcap

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

// AnalysisResult holds the outcome of offline PCAP analysis.
type AnalysisResult struct {
	Identifications  []Identification `json:"identifications"`
	onEvents         func([]dpi.Event, int)
	maxDisplayEvents int
	Events           []dpi.Event    `json:"events"`
	Flows            []FlowSummary  `json:"flows"`
	Protocols        map[string]int `json:"protocols"`
	Duration         time.Duration  `json:"duration"`
	PacketCount      int            `json:"packetCount"`
	ByteCount        int            `json:"byteCount"`
	// Truncated reports incomplete records or captured packets. A partial
	// record header cannot safely be attributed to any particular flow.
	Truncated        bool `json:"truncated"`
	DisplayTruncated bool `json:"displayTruncated"`
}

// FlowSummary describes a single network flow observed in the PCAP.
type FlowSummary struct {
	Key       string    `json:"key"`
	Protocol  string    `json:"protocol"`
	Packets   int       `json:"packets"`
	Bytes     int       `json:"bytes"`
	Events    int       `json:"events"` // All retained events, including identification, as in live rollups.
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
}

// analyzeCore parses offline traffic without generating permission.
func analyzeCore(r io.Reader, opts AnalysisOptions, decoders ...dpi.Decoder) (*AnalysisResult, error) {
	reader, err := newPCAPReader(r)
	if err != nil {
		return nil, fmt.Errorf("pcap header: %w", err)
	}

	// Advance a nondecreasing capture watermark for offline deadlines, while
	// Packet.At retains the original (possibly out-of-order) capture time.
	var watermark time.Time
	if opts.Now == nil {
		opts.Now = func() time.Time { return watermark }
	}
	mgr := dpi.NewManager(decoders...)
	sessions := newOfflineSessions()
	observer, err := newOfflineObserver(mgr, sessions, opts, decoders)
	if err != nil {
		return nil, err
	}

	flows := make(map[string]*flow.State)
	flowEvents := make(map[string]int)

	result := &AnalysisResult{
		Events:   []dpi.Event{},
		onEvents: opts.OnEvents, maxDisplayEvents: opts.MaxDisplayEvents,
		Identifications: []Identification{},
		Protocols:       make(map[string]int),
	}

	var firstTS, lastTS time.Time

	for {
		ts, data, truncated, err := reader.readRecord()
		if err == io.EOF {
			break
		}
		if err != nil {
			if err != io.ErrUnexpectedEOF {
				return nil, fmt.Errorf("pcap record: %w", err)
			}
			result.Truncated = true
			if data == nil {
				break // incomplete record header: no trustworthy tuple
			}
		}
		result.Truncated = result.Truncated || truncated
		updateAnalysisPacketStats(result, ts, len(data), &firstTS, &lastTS)
		if ts.After(watermark) {
			watermark = ts
		}
		observer.record(observer.observer.Sweep(opts.Now()), result, flowEvents)
		pkt, ok := decodeEthernetPacket(data)
		if !ok {
			continue
		}
		hash, state, reoriented := analysisFlowState(flows, pkt, ts)
		if opts.MaxFlows > 0 && len(flows) > opts.MaxFlows {
			return nil, fmt.Errorf("analysis flow budget exceeded")
		}
		for i := range reoriented {
			old := &reoriented[i]
			events, _ := mgr.OnFlowEnd(old)
			for i := range events {
				events[i].Connection = old.Connection.Load()
			}
			// Summaries use wire tuples independently of orientation.
			key := old.Key
			key.Dir = flow.DirForward
			recordAnalysisEvents(result, flowEvents, key.Hash(), events)
		}
		observer.record(observer.packet(pkt, state, ts, truncated), result, flowEvents)
		var events []dpi.Event
		if pkt.Invalid == "" && !truncated {
			events = analyzePacket(mgr, sessions, state, pkt, ts)
		}
		recordAnalysisEvents(result, flowEvents, hash, events)
	}

	observer.record(observer.observer.Drain(), result, flowEvents)
	finalizeAnalysisFlows(mgr, flows, result, flowEvents)

	result.Flows = buildFlowSummaries(flows, flowEvents)

	if !firstTS.IsZero() && !lastTS.IsZero() {
		result.Duration = lastTS.Sub(firstTS)
	}

	return result, nil
}

func updateAnalysisPacketStats(result *AnalysisResult, ts time.Time, size int, firstTS, lastTS *time.Time) {
	result.PacketCount++
	result.ByteCount += size
	if firstTS.IsZero() || ts.Before(*firstTS) {
		*firstTS = ts
	}
	if ts.After(*lastTS) {
		*lastTS = ts
	}
}

func analysisFlowState(flows map[string]*flow.State, pkt capture.Packet, ts time.Time) (string, *flow.State, []flow.State) {
	key := flow.Key{
		SrcIP:   pkt.SrcIP,
		DstIP:   pkt.DstIP,
		SrcPort: pkt.SrcPort,
		DstPort: pkt.DstPort,
		Proto:   pkt.Proto,
		Dir:     flow.DirForward,
	}
	hash := key.Hash()
	state, exists := flows[hash]
	opposite := key.Reversed()
	opposite.Dir = flow.DirForward
	reverse := flows[opposite.Hash()]
	var reoriented []flow.State
	// Map keys identify wire tuples; state keys additionally carry orientation.
	// A handshake always wins, including when it contradicts a midstream hint.
	if pkt.Proto == 6 && pkt.TCP.Flags&capture.TCPFlagSYN != 0 {
		if pkt.TCP.Flags&capture.TCPFlagACK != 0 {
			key.Dir = flow.DirReverse
		}
		if state != nil && state.Key.Dir != key.Dir {
			reoriented = append(reoriented, *state)
			state.Key.Dir = key.Dir
		}
		if reverse != nil && reverse.Key.Dir == key.Dir {
			reoriented = append(reoriented, *reverse)
			reverse.Key.Dir = key.Reversed().Dir
		}
	} else if exists {
		key.Dir = state.Key.Dir
	} else if reverse != nil {
		key.Dir = reverse.Key.Reversed().Dir
	} else {
		key.Dir, _ = flow.ICSServiceDirection(pkt.Proto, pkt.SrcPort, pkt.DstPort)
	}
	if !exists {
		state = flow.NewState(key, ts)
		flows[hash] = state
	}
	state.Touch(uint64(len(pkt.Payload)), ts)
	return hash, state, reoriented
}

// analyzePacket runs one packet through DPI with its TCP sequence number,
// as the live engine does. Events come before the error: a stream error's
// malformed event is among them and the analysis continues.
func analyzePacket(mgr *dpi.Manager, sessions *offlineSessions, state *flow.State, pkt capture.Packet, ts time.Time) []dpi.Event {
	parsed := &dpi.ParsedPacket{
		Timestamp:   ts,
		Payload:     pkt.Payload,
		Proto:       pkt.Transport,
		SrcPort:     pkt.SrcPort,
		DstPort:     pkt.DstPort,
		TCPSeq:      pkt.TCP.Seq,
		TCPSeqValid: pkt.TCP.Valid,
		TCPSyn:      pkt.TCP.Flags&capture.TCPFlagSYN != 0,
	}
	if parsed.TCPSyn {
		parsed.TCPSeq++
	}
	if iec, parse := sessions.annotate(mgr, pkt, parsed); iec && !parse {
		return nil
	}
	events, _ := mgr.OnPacket(state, parsed)
	for i := range events {
		events[i].Connection = state.Connection.Load()
	}
	return events
}

func recordAnalysisEvents(result *AnalysisResult, flowEvents map[string]int, hash string, events []dpi.Event) {
	if result.onEvents != nil {
		result.onEvents(events, result.PacketCount)
	}
	for _, ev := range events {
		if ev.Proto != eventfields.ProtoIdentify {
			result.Protocols[ev.Proto]++
		}
	}
	flowEvents[hash] += len(events)
	if result.maxDisplayEvents > 0 && len(result.Events)+len(events) > result.maxDisplayEvents {
		result.DisplayTruncated = true
		events = events[:max(0, result.maxDisplayEvents-len(result.Events))]
	}
	result.Events = append(result.Events, events...)
}

func finalizeAnalysisFlows(mgr *dpi.Manager, flows map[string]*flow.State, result *AnalysisResult, flowEvents map[string]int) {
	for hash, state := range flows {
		events, _ := mgr.OnFlowEnd(state)
		for i := range events {
			events[i].Connection = state.Connection.Load()
		}
		recordAnalysisEvents(result, flowEvents, hash, events)
	}
}

func buildFlowSummaries(flows map[string]*flow.State, flowEvents map[string]int) []FlowSummary {
	summaries := make([]FlowSummary, 0, len(flows))
	for hash, state := range flows {
		transport := flowTransport(state.Key.Proto)
		summaries = append(summaries, FlowSummary{
			Key:       fmt.Sprintf("%s:%d -> %s:%d (%s)", state.Key.SrcIP, state.Key.SrcPort, state.Key.DstIP, state.Key.DstPort, transport),
			Protocol:  transport,
			Packets:   int(state.Packets),
			Bytes:     int(state.Bytes),
			Events:    flowEvents[hash],
			FirstSeen: state.FirstSeen,
			LastSeen:  state.LastSeen,
		})
	}
	return summaries
}

func flowTransport(proto uint8) string {
	switch proto {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return "unknown"
	}
}

// Analyze reads a PCAP file from r, runs each packet through the supplied DPI
// decoders, and returns structured analysis results. It works entirely offline
// and does not require a network interface or Linux-specific APIs.
func Analyze(r io.Reader, decoders ...dpi.Decoder) (*AnalysisResult, error) {
	return AnalyzeWithOptions(r, AnalysisOptions{}, decoders...)
}

// AnalyzeWithOptions analyzes with a caller-owned rule snapshot and clock.
func AnalyzeWithOptions(r io.Reader, opts AnalysisOptions, decoders ...dpi.Decoder) (*AnalysisResult, error) {
	return analyzeCore(r, opts, decoders...)
}

// decodeEthernetPacket strips the Ethernet (and one 802.1Q) header and
// decodes the IP packet with capture.DecodeIPPacket, the decoder the live
// capture path uses. Packets without usable headers are skipped; truncated TCP payload is
// passed only to the observer, never to the legacy decoder.
func decodeEthernetPacket(data []byte) (capture.Packet, bool) {
	if len(data) < 14 {
		return capture.Packet{}, false
	}
	// EtherType is at bytes 12-13.
	etherType := binary.BigEndian.Uint16(data[12:14])
	ipData := data[14:]

	// Handle 802.1Q VLAN tagging.
	if etherType == 0x8100 {
		if len(ipData) < 4 {
			return capture.Packet{}, false
		}
		etherType = binary.BigEndian.Uint16(ipData[2:4])
		ipData = ipData[4:]
	}
	if etherType != 0x0800 && etherType != 0x86DD {
		return capture.Packet{}, false
	}
	pkt := capture.DecodeIPPacket(ipData)
	return pkt, pkt.Invalid == "" || pkt.Invalid == capture.InvalidTruncated && pkt.TCP.Valid
}
