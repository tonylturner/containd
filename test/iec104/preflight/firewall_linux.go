// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"

	nfqueue "github.com/florianl/go-nfqueue/v2"
	"golang.org/x/sys/unix"
)

type firewallState struct {
	mu              sync.Mutex
	queue           *nfqueue.Nfqueue
	queueCancel     context.CancelFunc
	queueActive     bool
	currentRule     rule
	held            map[uint32]packet
	events          []packet
	flows           map[uint16]sequenceState
	callbacks       uint64
	verdictsNoError uint64
	verdictErrors   []string
	setVerdictTimes []int64
	handlerTimes    []int64
	maxPacket       int
	stopErr         string
}

func runFirewall() error {
	state := &firewallState{
		held:  make(map[uint32]packet),
		flows: make(map[uint16]sequenceState),
	}
	if err := state.startQueue(); err != nil {
		return fmt.Errorf("bind NFQUEUE %d: %w", queueNumber, err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", state.handleHealth)
	mux.HandleFunc("/rule", state.handleRule)
	mux.HandleFunc("/held", state.handleHeld)
	mux.HandleFunc("/verdict", state.handleVerdict)
	mux.HandleFunc("/events", state.handleEvents)
	mux.HandleFunc("/stats", state.handleStats)
	mux.HandleFunc("/sequences", state.handleSequences)
	mux.HandleFunc("/inject-rst", state.handleInjectRST)
	mux.HandleFunc("/clear-events", state.handleClearEvents)
	mux.HandleFunc("/queue/stop", state.handleStopQueue)
	return controlHandler("127.0.0.1:8081", mux)
}

func (s *firewallState) startQueue() error {
	queue, err := nfqueue.Open(&nfqueue.Config{
		NfQueue:      queueNumber,
		MaxQueueLen:  1024,
		MaxPacketLen: 65535,
		Copymode:     nfqueue.NfQnlCopyPacket,
		AfFamily:     unix.AF_INET,
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := queue.RegisterWithErrorFunc(ctx, s.onPacket, func(err error) int {
		if ctx.Err() != nil {
			return 1
		}
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
			return 0
		}
		return 1
	}); err != nil {
		cancel()
		_ = queue.Close()
		return err
	}
	s.mu.Lock()
	s.queue = queue
	s.queueCancel = cancel
	s.queueActive = true
	s.mu.Unlock()
	return nil
}

func (s *firewallState) onPacket(attr nfqueue.Attribute) int {
	if attr.PacketID == nil || attr.Payload == nil {
		return 0
	}
	p, payload, ok := parsePacket(*attr.PacketID, *attr.Payload)
	if !ok {
		return 0
	}
	s.mu.Lock()
	s.callbacks++
	if p.PacketLen > s.maxPacket {
		s.maxPacket = p.PacketLen
	}
	s.trackSequenceLocked(p)
	currentRule := s.currentRule
	if currentRule.Prefix != "" &&
		(currentRule.Direction == "both" || currentRule.Direction == p.Direction) &&
		len(payload) >= len(currentRule.Prefix) &&
		string(payload[:len(currentRule.Prefix)]) == currentRule.Prefix {
		p.Matched = true
		p.Held = true
		p.HeldAt = time.Now()
		s.held[p.ID] = p
	}
	s.events = append(s.events, p)
	if len(s.events) > 20000 {
		s.events = append([]packet(nil), s.events[len(s.events)-10000:]...)
	}
	shouldHold := p.Matched
	s.mu.Unlock()

	if shouldHold {
		if currentRule.Action == "manual" {
			return 0
		}
		delay := time.Duration(currentRule.DelayMS) * time.Millisecond
		time.AfterFunc(delay, func() {
			if err := s.submitVerdict(p.ID, currentRule.Action); err != nil {
				return
			}
		})
		return 0
	}
	if err := s.submitVerdict(p.ID, "accept"); err != nil {
		return 0
	}
	return 0
}

func (s *firewallState) trackSequenceLocked(p packet) {
	if p.SrcPort != serverPort && p.DstPort != serverPort {
		return
	}
	clientPort := p.SrcPort
	if p.Direction == "s2c" {
		clientPort = p.DstPort
	}
	if p.Direction != "c2s" && p.Direction != "s2c" {
		return
	}
	flow := s.flows[clientPort]
	flow.ClientPort = clientPort
	if p.Flags&0x10 != 0 {
		if p.Direction == "c2s" {
			flow.ExpectedClient = p.Ack
		} else {
			flow.ExpectedServer = p.Ack
		}
		flow.UpdatedAt = p.ObservedAt
		s.flows[clientPort] = flow
	}
}

func (s *firewallState) submitVerdict(id uint32, action string) error {
	s.mu.Lock()
	queue := s.queue
	entry, held := s.held[id]
	if held {
		delete(s.held, id)
	}
	s.mu.Unlock()
	if queue == nil {
		return fmt.Errorf("queue is not active")
	}
	verdict := nfqueue.NfAccept
	if action == "drop" {
		verdict = nfqueue.NfDrop
	} else if action != "accept" {
		return fmt.Errorf("unsupported verdict action %q", action)
	}
	started := time.Now()
	err := queue.SetVerdict(id, verdict)
	elapsed := time.Since(started)
	s.mu.Lock()
	s.setVerdictTimes = append(s.setVerdictTimes, int64(elapsed))
	if err == nil {
		s.verdictsNoError++
	} else {
		s.verdictErrors = append(s.verdictErrors, fmt.Sprintf("packet %d %s: %v", id, action, err))
	}
	for i := range s.events {
		if s.events[i].ID == id {
			s.events[i].Verdict = action
			s.events[i].ResolvedAt = time.Now()
			s.events[i].VerdictMS = float64(elapsed) / float64(time.Millisecond)
			if held {
				s.events[i].HoldMS = s.events[i].ResolvedAt.Sub(entry.HeldAt).Seconds() * 1000
			}
			if err != nil {
				s.events[i].VerdictErr = err.Error()
			}
			break
		}
	}
	s.mu.Unlock()
	return err
}

func (s *firewallState) handleHealth(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	active := s.queueActive
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "queue_active": active})
}

func (s *firewallState) handleRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("POST required"))
		return
	}
	var next rule
	if err := decodeJSON(r, &next); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if next.Prefix == "" {
		next = rule{}
	} else if (next.Direction != "c2s" && next.Direction != "s2c" && next.Direction != "both") ||
		(next.Action != "accept" && next.Action != "drop" && next.Action != "manual") ||
		next.DelayMS < 0 || next.DelayMS > 10000 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid rule"))
		return
	}
	s.mu.Lock()
	s.currentRule = next
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, next)
}

func (s *firewallState) handleHeld(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("GET required"))
		return
	}
	s.mu.Lock()
	held := make([]packet, 0, len(s.held))
	for _, entry := range s.held {
		held = append(held, entry)
	}
	s.mu.Unlock()
	sort.Slice(held, func(i, j int) bool {
		return held[i].ObservedAt.Before(held[j].ObservedAt)
	})
	writeJSON(w, http.StatusOK, map[string]any{"held": held})
}

func (s *firewallState) handleVerdict(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	defer func() {
		s.mu.Lock()
		s.handlerTimes = append(s.handlerTimes, int64(time.Since(started)))
		s.mu.Unlock()
	}()
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("POST required"))
		return
	}
	var req verdictRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if req.Action != "accept" && req.Action != "drop" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("action must be accept or drop"))
		return
	}
	s.mu.Lock()
	_, found := s.held[req.ID]
	s.mu.Unlock()
	if !found {
		writeError(w, http.StatusNotFound, fmt.Errorf("packet %d is not held", req.ID))
		return
	}
	if err := s.submitVerdict(req.ID, req.Action); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": req.ID, "action": req.Action, "submitted": true})
}

func (s *firewallState) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("GET required"))
		return
	}
	s.mu.Lock()
	events := append([]packet(nil), s.events...)
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (s *firewallState) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("GET required"))
		return
	}
	s.mu.Lock()
	stats := map[string]any{
		"callbacks":               s.callbacks,
		"verdicts_setverdict_nil": s.verdictsNoError,
		"verdict_errors":          append([]string{}, s.verdictErrors...),
		"held":                    len(s.held),
		"queue_active":            s.queueActive,
		"max_observed_packet":     s.maxPacket,
		"max_packet_len_config":   65535,
		"stop_error":              s.stopErr,
		"setverdict_latency":      summarizeLatencies(s.setVerdictTimes),
		"verdict_handler_latency": summarizeLatencies(s.handlerTimes),
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, stats)
}

func summarizeLatencies(samples []int64) map[string]any {
	ordered := append([]int64(nil), samples...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	summary := map[string]any{"count": len(ordered), "max_ms": 0.0, "p99_ms": 0.0}
	if len(ordered) == 0 {
		return summary
	}
	p99Index := int(math.Ceil(float64(len(ordered))*0.99)) - 1
	summary["max_ms"] = float64(ordered[len(ordered)-1]) / float64(time.Millisecond)
	summary["p99_ms"] = float64(ordered[p99Index]) / float64(time.Millisecond)
	return summary
}

func (s *firewallState) handleSequences(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("GET required"))
		return
	}
	port, err := strconv.Atoi(r.URL.Query().Get("client_port"))
	if err != nil || port < 1 || port > 65535 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("client_port must be 1..65535"))
		return
	}
	s.mu.Lock()
	flow, found := s.flows[uint16(port)]
	s.mu.Unlock()
	if !found {
		writeError(w, http.StatusNotFound, fmt.Errorf("no sequence observations for port %d", port))
		return
	}
	writeJSON(w, http.StatusOK, flow)
}

func (s *firewallState) handleInjectRST(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("POST required"))
		return
	}
	var req rstRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var src, dst netip.Addr
	var srcPort, dstPort uint16
	switch req.Target {
	case "client":
		src, dst = netip.MustParseAddr(serverIP), netip.MustParseAddr(clientIP)
		srcPort, dstPort = serverPort, req.ClientPort
	case "server":
		src, dst = netip.MustParseAddr(clientIP), netip.MustParseAddr(serverIP)
		srcPort, dstPort = req.ClientPort, serverPort
	default:
		writeError(w, http.StatusBadRequest, fmt.Errorf("target must be client or server"))
		return
	}
	if req.ClientPort == 0 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("client_port must be nonzero"))
		return
	}
	if err := sendRawRST(src, dst, srcPort, dstPort, req.Seq); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"target": req.Target, "seq": req.Seq, "src_ip": src.String(), "dst_ip": dst.String(),
		"src_port": srcPort, "dst_port": dstPort, "written": true,
	})
}

func (s *firewallState) handleClearEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("POST required"))
		return
	}
	s.mu.Lock()
	s.events = nil
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]bool{"cleared": true})
}

func (s *firewallState) handleStopQueue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("POST required"))
		return
	}
	s.mu.Lock()
	if !s.queueActive || s.queue == nil {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, fmt.Errorf("queue is already stopped"))
		return
	}
	cancel, queue := s.queueCancel, s.queue
	s.queueActive = false
	s.queue = nil
	s.mu.Unlock()
	cancel()
	err := queue.Close()
	s.mu.Lock()
	if err != nil {
		s.stopErr = err.Error()
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"stopped": true, "close_error": errorString(err)})
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func sendRawRST(src, dst netip.Addr, srcPort, dstPort uint16, seq uint32) error {
	if !src.Is4() || !dst.Is4() {
		return fmt.Errorf("raw RST only supports IPv4")
	}
	packet := make([]byte, 40)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = syscall.IPPROTO_TCP
	src4, dst4 := src.As4(), dst.As4()
	copy(packet[12:16], src4[:])
	copy(packet[16:20], dst4[:])
	binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:20]))

	tcp := packet[20:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	tcp[12] = 5 << 4
	tcp[13] = 0x04
	pseudo := make([]byte, 12+len(tcp))
	copy(pseudo[0:4], src4[:])
	copy(pseudo[4:8], dst4[:])
	pseudo[9] = syscall.IPPROTO_TCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcp)))
	copy(pseudo[12:], tcp)
	binary.BigEndian.PutUint16(tcp[16:18], checksum(pseudo))

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
	if err != nil {
		return fmt.Errorf("open IP_HDRINCL raw socket: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		return fmt.Errorf("set IP_HDRINCL: %w", err)
	}
	if err := unix.Sendto(fd, packet, 0, &unix.SockaddrInet4{Addr: dst4}); err != nil {
		return fmt.Errorf("send RST to %s:%d seq=%d: %w", dst, dstPort, seq, err)
	}
	return nil
}

func checksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
