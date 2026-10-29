// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package pcap

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/ics"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/learn"
)

const maxPCAPRecordSize = 16 << 20 // 16 MiB

// AnalysisResult holds the outcome of offline PCAP analysis.
type AnalysisResult struct {
	Identifications []Identification `json:"identifications"`
	observed        map[string]bool
	Events          []dpi.Event    `json:"events"`
	Flows           []FlowSummary  `json:"flows"`
	Protocols       map[string]int `json:"protocols"`
	Duration        time.Duration  `json:"duration"`
	PacketCount     int            `json:"packetCount"`
	ByteCount       int            `json:"byteCount"`
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

// eventCallback is called for each DPI event with the source and destination
// IPs of the packet that produced it. Used by AnalyzeForPolicy to feed events
// to the learner without re-parsing the PCAP.
type eventCallback func(srcIP, dstIP string, ev dpi.Event)

// analyzeCore is the shared PCAP analysis loop used by both Analyze and
// AnalyzeForPolicy. If onEvent is non-nil it is called for each DPI event
// with the packet-level source and destination IPs.
func analyzeCore(r io.Reader, opts AnalysisOptions, onEvent eventCallback, decoders ...dpi.Decoder) (*AnalysisResult, error) {
	snaplen, err := readPCAPHeader(r)
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
	observer, err := newOfflineObserver(sessions.runID, opts, decoders)
	if err != nil {
		return nil, err
	}

	flows := make(map[string]*flow.State)
	flowEvents := make(map[string]int)

	result := &AnalysisResult{
		Events:          []dpi.Event{},
		Identifications: []Identification{},
		observed:        map[string]bool{},
		Protocols:       make(map[string]int),
	}

	var firstTS, lastTS time.Time

	for {
		ts, data, truncated, err := readPCAPRecord(r, snaplen)
		if err != nil {
			if endOfPCAP(err) {
				break
			}
			return nil, fmt.Errorf("pcap record: %w", err)
		}
		updateAnalysisPacketStats(result, ts, len(data), &firstTS, &lastTS)
		if ts.After(watermark) {
			watermark = ts
		}
		observer.record(observer.observer.Sweep(opts.Now()), result, flowEvents, onEvent)
		pkt, ok := decodeEthernetPacket(data)
		if !ok {
			continue
		}
		hash, state, reoriented := analysisFlowState(flows, pkt, ts)
		for i := range reoriented {
			old := &reoriented[i]
			events, _ := mgr.OnFlowEnd(old)
			for i := range events {
				events[i].Connection = old.Connection.Load()
			}
			// Summaries use wire tuples independently of orientation.
			key := old.Key
			key.Dir = flow.DirForward
			recordAnalysisEvents(result, flowEvents, key.Hash(), key.SrcIP.String(), key.DstIP.String(), events, onEvent)
		}
		observer.record(observer.packet(pkt, state, ts, truncated), result, flowEvents, onEvent)
		var events []dpi.Event
		if pkt.Invalid == "" {
			events = analyzePacket(mgr, sessions, state, pkt, ts)
		}
		recordAnalysisEvents(result, flowEvents, hash, pkt.SrcIP.String(), pkt.DstIP.String(), events, onEvent)
	}

	observer.record(observer.observer.Drain(), result, flowEvents, onEvent)
	finalizeAnalysisFlows(mgr, flows, result, flowEvents, onEvent)

	result.Flows = buildFlowSummaries(flows, flowEvents)

	if !firstTS.IsZero() && !lastTS.IsZero() {
		result.Duration = lastTS.Sub(firstTS)
	}

	return result, nil
}

func endOfPCAP(err error) bool {
	return err == io.EOF || err == io.ErrUnexpectedEOF
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

func recordAnalysisEvents(result *AnalysisResult, flowEvents map[string]int, hash, srcStr, dstStr string, events []dpi.Event, onEvent eventCallback) {
	for _, ev := range events {
		if onEvent != nil {
			onEvent(srcStr, dstStr, ev)
		}
		if ev.Proto != eventfields.ProtoIdentify {
			result.Protocols[ev.Proto]++
		}
	}
	result.Events = append(result.Events, events...)
	flowEvents[hash] += len(events)
}

func finalizeAnalysisFlows(mgr *dpi.Manager, flows map[string]*flow.State, result *AnalysisResult, flowEvents map[string]int, onEvent eventCallback) {
	for hash, state := range flows {
		events, _ := mgr.OnFlowEnd(state)
		for i := range events {
			events[i].Connection = state.Connection.Load()
		}
		recordAnalysisEvents(result, flowEvents, hash, state.Key.SrcIP.String(), state.Key.DstIP.String(), events, onEvent)
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
	return analyzeCore(r, opts, nil, decoders...)
}

// PolicyAnalysis holds the outcome of PCAP-to-policy analysis, combining
// the standard analysis stats with auto-generated firewall rules.
type PolicyAnalysis struct {
	Rules        []config.Rule          `json:"rules"`
	Profiles     []learn.LearnedProfile `json:"profiles"`
	Stats        AnalysisResult         `json:"stats"`
	EventSummary map[string]int         `json:"eventSummary"`
}

// AnalyzeForPolicy reads a PCAP file, runs DPI analysis, and generates
// allowlist firewall rules from the observed traffic. Rules are returned
// for review and are not auto-applied.
func AnalyzeForPolicy(r io.Reader, decoders ...dpi.Decoder) (*PolicyAnalysis, error) {
	learner := learn.New()
	eventSummary := make(map[string]int)

	type candidate struct {
		src, dst string
		ev       dpi.Event
	}
	var candidates []candidate
	onEvent := func(srcIP, dstIP string, ev dpi.Event) {
		if ev.Proto == eventfields.ProtoIdentify {
			return
		}
		eventSummary[ev.Proto]++
		// IT/utility traffic remains visible in analysis, not ICS policy.
		// IEC104 is also summarised but never auto-learned.
		if ics.Learnable(strings.ToLower(ev.Proto)) {
			candidates = append(candidates, candidate{srcIP, dstIP, ev})
		}
	}

	result, err := analyzeCore(r, AnalysisOptions{}, onEvent, decoders...)
	if err != nil {
		return nil, err
	}

	for _, c := range candidates {
		if c.ev.Connection != nil && result.observed[c.ev.Connection.Key] {
			continue
		}
		learner.RecordEvent(c.src, c.dst, c.ev)
	}

	return &PolicyAnalysis{
		Rules:        learner.GenerateRules(),
		Profiles:     learner.Profiles(),
		Stats:        *result,
		EventSummary: eventSummary,
	}, nil
}

// pcapMagicLE is the PCAP magic number in little-endian byte order.
const pcapMagicLE = 0xa1b2c3d4

// pcapMagicBE is the PCAP magic number in big-endian byte order (swapped).
const pcapMagicBE = 0xd4c3b2a1

// readPCAPHeader reads and validates the 24-byte PCAP global header.
func readPCAPHeader(r io.Reader) (uint32, error) {
	header := make([]byte, 24)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, err
	}
	magic := binary.LittleEndian.Uint32(header[0:])
	if magic != pcapMagicLE && magic != pcapMagicBE {
		return 0, fmt.Errorf("invalid pcap magic: 0x%08x", magic)
	}
	snaplen := binary.LittleEndian.Uint32(header[16:])
	if magic == pcapMagicBE {
		snaplen = binary.BigEndian.Uint32(header[16:])
	}
	return snaplen, nil
}

// readPCAPRecord reads a single PCAP packet record (16-byte header + data).
func readPCAPRecord(r io.Reader, snaplen uint32) (time.Time, []byte, bool, error) {
	rec := make([]byte, 16)
	if _, err := io.ReadFull(r, rec); err != nil {
		return time.Time{}, nil, false, err
	}
	sec := binary.LittleEndian.Uint32(rec[0:])
	usec := binary.LittleEndian.Uint32(rec[4:])
	inclLen := binary.LittleEndian.Uint32(rec[8:])
	truncated := binary.LittleEndian.Uint32(rec[12:]) > inclLen
	if snaplen > 0 && inclLen > snaplen {
		return time.Time{}, nil, false, fmt.Errorf("invalid captured length %d exceeds snaplen %d", inclLen, snaplen)
	}
	if inclLen > maxPCAPRecordSize {
		return time.Time{}, nil, false, fmt.Errorf("invalid captured length %d exceeds maximum %d", inclLen, maxPCAPRecordSize)
	}
	if inclLen == 0 {
		return time.Unix(int64(sec), int64(usec)*1000), nil, truncated, nil
	}
	data := make([]byte, inclLen)
	if _, err := io.ReadFull(r, data); err != nil {
		return time.Time{}, nil, false, err
	}
	ts := time.Unix(int64(sec), int64(usec)*1000)
	return ts, data, truncated, nil
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
