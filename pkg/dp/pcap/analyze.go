// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package pcap

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"github.com/tonylturner/containd/pkg/dp/learn"
)

const maxPCAPRecordSize = 16 << 20 // 16 MiB

// AnalysisResult holds the outcome of offline PCAP analysis.
type AnalysisResult struct {
	Events      []dpi.Event    `json:"events"`
	Flows       []FlowSummary  `json:"flows"`
	Protocols   map[string]int `json:"protocols"`
	Duration    time.Duration  `json:"duration"`
	PacketCount int            `json:"packetCount"`
	ByteCount   int            `json:"byteCount"`
}

// FlowSummary describes a single network flow observed in the PCAP.
type FlowSummary struct {
	Key       string    `json:"key"`
	Protocol  string    `json:"protocol"`
	Packets   int       `json:"packets"`
	Bytes     int       `json:"bytes"`
	Events    int       `json:"events"`
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
func analyzeCore(r io.Reader, onEvent eventCallback, decoders ...dpi.Decoder) (*AnalysisResult, error) {
	snaplen, err := readPCAPHeader(r)
	if err != nil {
		return nil, fmt.Errorf("pcap header: %w", err)
	}

	mgr := dpi.NewManager(decoders...)

	flows := make(map[string]*flow.State)
	flowEvents := make(map[string]int)

	result := &AnalysisResult{
		Events:    []dpi.Event{},
		Protocols: make(map[string]int),
	}

	var firstTS, lastTS time.Time

	for {
		ts, data, err := readPCAPRecord(r, snaplen)
		if err != nil {
			if endOfPCAP(err) {
				break
			}
			return nil, fmt.Errorf("pcap record: %w", err)
		}
		updateAnalysisPacketStats(result, ts, len(data), &firstTS, &lastTS)
		pkt, ok := decodeEthernetPacket(data, ts)
		if !ok {
			continue
		}
		hash, state := analysisFlowState(flows, pkt, ts)
		events, err := analyzePacket(mgr, state, pkt, ts)
		if err != nil {
			continue
		}
		recordAnalysisEvents(result, flowEvents, hash, pkt.srcIP.String(), pkt.dstIP.String(), events, onEvent)
	}

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

func analysisFlowState(flows map[string]*flow.State, pkt parsedPacketInfo, ts time.Time) (string, *flow.State) {
	key := flow.Key{
		SrcIP:   pkt.srcIP,
		DstIP:   pkt.dstIP,
		SrcPort: pkt.srcPort,
		DstPort: pkt.dstPort,
		Proto:   pkt.proto,
		Dir:     flow.DirForward,
	}
	hash := key.Hash()
	state, exists := flows[hash]
	if !exists {
		state = flow.NewState(key, ts)
		flows[hash] = state
	}
	state.Touch(uint64(len(pkt.payload)), ts)
	return hash, state
}

func analyzePacket(mgr *dpi.Manager, state *flow.State, pkt parsedPacketInfo, ts time.Time) ([]dpi.Event, error) {
	parsed := &dpi.ParsedPacket{
		Payload: pkt.payload,
		Proto:   pkt.transport,
		SrcPort: pkt.srcPort,
		DstPort: pkt.dstPort,
	}
	events, err := mgr.OnPacket(state, parsed)
	if err != nil {
		return nil, err
	}
	for i := range events {
		if events[i].Timestamp.IsZero() {
			events[i].Timestamp = ts
		}
	}
	return events, nil
}

func recordAnalysisEvents(result *AnalysisResult, flowEvents map[string]int, hash, srcStr, dstStr string, events []dpi.Event, onEvent eventCallback) {
	for _, ev := range events {
		if onEvent != nil {
			onEvent(srcStr, dstStr, ev)
		}
		result.Protocols[ev.Proto]++
	}
	result.Events = append(result.Events, events...)
	flowEvents[hash] += len(events)
}

func finalizeAnalysisFlows(mgr *dpi.Manager, flows map[string]*flow.State, result *AnalysisResult, flowEvents map[string]int, onEvent eventCallback) {
	for hash, state := range flows {
		events, err := mgr.OnFlowEnd(state)
		if err != nil {
			continue
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
	return analyzeCore(r, nil, decoders...)
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

	onEvent := func(srcIP, dstIP string, ev dpi.Event) {
		eventSummary[ev.Proto]++
		learner.RecordEvent(srcIP, dstIP, ev)
	}

	result, err := analyzeCore(r, onEvent, decoders...)
	if err != nil {
		return nil, err
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
func readPCAPRecord(r io.Reader, snaplen uint32) (time.Time, []byte, error) {
	rec := make([]byte, 16)
	if _, err := io.ReadFull(r, rec); err != nil {
		return time.Time{}, nil, err
	}
	sec := binary.LittleEndian.Uint32(rec[0:])
	usec := binary.LittleEndian.Uint32(rec[4:])
	inclLen := binary.LittleEndian.Uint32(rec[8:])
	if snaplen > 0 && inclLen > snaplen {
		return time.Time{}, nil, fmt.Errorf("invalid captured length %d exceeds snaplen %d", inclLen, snaplen)
	}
	if inclLen > maxPCAPRecordSize {
		return time.Time{}, nil, fmt.Errorf("invalid captured length %d exceeds maximum %d", inclLen, maxPCAPRecordSize)
	}
	if inclLen == 0 {
		return time.Unix(int64(sec), int64(usec)*1000), nil, nil
	}
	data := make([]byte, inclLen)
	if _, err := io.ReadFull(r, data); err != nil {
		return time.Time{}, nil, err
	}
	ts := time.Unix(int64(sec), int64(usec)*1000)
	return ts, data, nil
}

// parsedPacketInfo holds the result of parsing an Ethernet/IP/TCP|UDP packet.
type parsedPacketInfo struct {
	srcIP     net.IP
	dstIP     net.IP
	srcPort   uint16
	dstPort   uint16
	proto     uint8
	transport string
	payload   []byte
}

// decodeEthernetPacket decodes an Ethernet frame containing an IP packet.
// It strips the 14-byte Ethernet header and parses the IP + L4 headers.
func decodeEthernetPacket(data []byte, ts time.Time) (parsedPacketInfo, bool) {
	if len(data) < 14 {
		return parsedPacketInfo{}, false
	}
	// EtherType is at bytes 12-13.
	etherType := binary.BigEndian.Uint16(data[12:14])
	ipData := data[14:]

	// Handle 802.1Q VLAN tagging.
	if etherType == 0x8100 {
		if len(ipData) < 4 {
			return parsedPacketInfo{}, false
		}
		etherType = binary.BigEndian.Uint16(ipData[2:4])
		ipData = ipData[4:]
	}

	switch etherType {
	case 0x0800: // IPv4
		return decodeIPv4Packet(ipData)
	case 0x86DD: // IPv6
		return decodeIPv6Packet(ipData)
	default:
		return parsedPacketInfo{}, false
	}
}

func decodeIPv4Packet(data []byte) (parsedPacketInfo, bool) {
	if len(data) < 20 {
		return parsedPacketInfo{}, false
	}
	ihl := int(data[0]&0x0f) * 4
	if ihl < 20 || len(data) < ihl {
		return parsedPacketInfo{}, false
	}
	proto := data[9]
	src := net.IPv4(data[12], data[13], data[14], data[15])
	dst := net.IPv4(data[16], data[17], data[18], data[19])
	return decodeL4(proto, src, dst, data[ihl:])
}

func decodeIPv6Packet(data []byte) (parsedPacketInfo, bool) {
	if len(data) < 40 {
		return parsedPacketInfo{}, false
	}
	proto := data[6]
	src := net.IP(append([]byte(nil), data[8:24]...))
	dst := net.IP(append([]byte(nil), data[24:40]...))
	return decodeL4(proto, src, dst, data[40:])
}

func decodeL4(proto uint8, src, dst net.IP, data []byte) (parsedPacketInfo, bool) {
	switch proto {
	case 6: // TCP
		if len(data) < 20 {
			return parsedPacketInfo{}, false
		}
		sport := binary.BigEndian.Uint16(data[0:2])
		dport := binary.BigEndian.Uint16(data[2:4])
		off := int(data[12]>>4) * 4
		if off < 20 || len(data) < off {
			return parsedPacketInfo{}, false
		}
		payload := append([]byte(nil), data[off:]...)
		return parsedPacketInfo{
			srcIP: src, dstIP: dst,
			srcPort: sport, dstPort: dport,
			proto: proto, transport: "tcp",
			payload: payload,
		}, true
	case 17: // UDP
		if len(data) < 8 {
			return parsedPacketInfo{}, false
		}
		sport := binary.BigEndian.Uint16(data[0:2])
		dport := binary.BigEndian.Uint16(data[2:4])
		payload := append([]byte(nil), data[8:]...)
		return parsedPacketInfo{
			srcIP: src, dstIP: dst,
			srcPort: sport, dstPort: dport,
			proto: proto, transport: "udp",
			payload: payload,
		}, true
	default:
		return parsedPacketInfo{}, false
	}
}
