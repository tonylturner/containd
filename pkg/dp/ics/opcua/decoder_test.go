// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package opcua

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

func TestParseFrameHEL(t *testing.T) {
	raw := make([]byte, 32)
	copy(raw[0:3], "HEL")
	raw[3] = 'F'
	binary.LittleEndian.PutUint32(raw[4:8], 32)

	f, err := ParseFrame(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if f.MessageType != MsgTypeHEL {
		t.Fatalf("unexpected message type: %s", f.MessageType)
	}
	if f.ChunkType != ChunkFinal {
		t.Fatalf("unexpected chunk type: %c", f.ChunkType)
	}
	if f.MessageSize != 32 {
		t.Fatalf("unexpected size: %d", f.MessageSize)
	}
	if !IsSessionMessage(f.MessageType) {
		t.Fatal("HEL should be session message")
	}
}

func TestParseFrameMSGWithService(t *testing.T) {
	// Build a MSG with a four-byte node ID encoding for ReadRequest.
	raw := make([]byte, 28)
	copy(raw[0:3], "MSG")
	raw[3] = 'F'
	binary.LittleEndian.PutUint32(raw[4:8], 28)
	// SecureChannelId(4) + SecurityTokenId(4) + SeqNum(4) + RequestId(4) = 16 bytes at offset 8
	// Node ID at offset 24: four-byte encoding (0x01), namespace=0, id=ServiceReadRequest
	raw[24] = 0x01 // four-byte node ID encoding
	raw[25] = 0x00 // namespace
	binary.LittleEndian.PutUint16(raw[26:28], ServiceReadRequest)

	f, err := ParseFrame(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if f.MessageType != MsgTypeMSG {
		t.Fatalf("unexpected message type: %s", f.MessageType)
	}
	if !f.HasService {
		t.Fatal("expected HasService=true")
	}
	if f.ServiceNodeID != ServiceReadRequest {
		t.Fatalf("unexpected service node ID: %d", f.ServiceNodeID)
	}
	if ServiceName(f.ServiceNodeID) != "read-request" {
		t.Fatalf("unexpected service name: %s", ServiceName(f.ServiceNodeID))
	}
	if IsWriteService(f.ServiceNodeID) {
		t.Fatal("ReadRequest should not be a write service")
	}
}

func TestParseFrameMSGWriteRequest(t *testing.T) {
	raw := make([]byte, 28)
	copy(raw[0:3], "MSG")
	raw[3] = 'F'
	binary.LittleEndian.PutUint32(raw[4:8], 28)
	raw[24] = 0x01
	raw[25] = 0x00
	binary.LittleEndian.PutUint16(raw[26:28], ServiceWriteRequest)

	f, err := ParseFrame(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !IsWriteService(f.ServiceNodeID) {
		t.Fatal("WriteRequest should be a write service")
	}
	if ServiceName(f.ServiceNodeID) != "write-request" {
		t.Fatalf("unexpected service name: %s", ServiceName(f.ServiceNodeID))
	}
}

func TestParseFrameTooShort(t *testing.T) {
	if _, err := ParseFrame([]byte("MS")); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseFrameInvalidType(t *testing.T) {
	raw := make([]byte, 8)
	copy(raw[0:3], "XXX")
	raw[3] = 'F'
	binary.LittleEndian.PutUint32(raw[4:8], 8)
	_, err := ParseFrame(raw)
	if err == nil {
		t.Fatal("expected error for invalid message type")
	}
}

func TestParseFrameTwoByteNodeID(t *testing.T) {
	// MSG with two-byte node ID encoding: id=42
	raw := make([]byte, 26)
	copy(raw[0:3], "MSG")
	raw[3] = 'F'
	binary.LittleEndian.PutUint32(raw[4:8], 26)
	raw[24] = 0x00 // two-byte encoding
	raw[25] = 42

	f, err := ParseFrame(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !f.HasService || f.ServiceNodeID != 42 {
		t.Fatalf("unexpected: HasService=%v, NodeID=%d", f.HasService, f.ServiceNodeID)
	}
}

func TestServiceNameCoverage(t *testing.T) {
	tests := []struct {
		id   uint16
		want string
	}{
		{ServiceReadRequest, "read-request"},
		{ServiceReadResponse, "read-response"},
		{ServiceWriteRequest, "write-request"},
		{ServiceWriteResponse, "write-response"},
		{ServiceHistoryReadRequest, "history-read-request"},
		{ServiceHistoryReadResponse, "history-read-response"},
		{ServiceHistoryUpdateRequest, "history-update-request"},
		{ServiceHistoryUpdateResponse, "history-update-response"},
		{ServiceBrowseRequest, "browse-request"},
		{ServiceBrowseResponse, "browse-response"},
		{ServiceBrowseNextRequest, "browse-next-request"},
		{ServiceBrowseNextResponse, "browse-next-response"},
		{ServiceCreateSessionRequest, "create-session-request"},
		{ServiceCreateSessionResponse, "create-session-response"},
		{ServiceActivateSessionRequest, "activate-session-request"},
		{ServiceActivateSessionResponse, "activate-session-response"},
		{ServiceCloseSessionRequest, "close-session-request"},
		{ServiceCloseSessionResponse, "close-session-response"},
		{ServiceAddNodesRequest, "add-nodes-request"},
		{ServiceAddNodesResponse, "add-nodes-response"},
		{ServiceDeleteNodesRequest, "delete-nodes-request"},
		{ServiceDeleteNodesResponse, "delete-nodes-response"},
		{ServiceCreateSubscriptionRequest, "create-subscription-request"},
		{ServiceCreateSubscriptionResponse, "create-subscription-response"},
		{ServiceModifySubscriptionRequest, "modify-subscription-request"},
		{ServiceModifySubscriptionResponse, "modify-subscription-response"},
		{ServiceDeleteSubscriptionsRequest, "delete-subscriptions-request"},
		{ServiceDeleteSubscriptionsResponse, "delete-subscriptions-response"},
		{ServicePublishRequest, "publish-request"},
		{ServicePublishResponse, "publish-response"},
		{ServiceCreateMonitoredItemsRequest, "create-monitored-items-request"},
		{ServiceCreateMonitoredItemsResponse, "create-monitored-items-response"},
		{ServiceDeleteMonitoredItemsRequest, "delete-monitored-items-request"},
		{ServiceDeleteMonitoredItemsResponse, "delete-monitored-items-response"},
		{ServiceCallRequest, "call-request"},
		{ServiceCallResponse, "call-response"},
		{9999, "service-9999"},
	}
	for _, tt := range tests {
		got := ServiceName(tt.id)
		if got != tt.want {
			t.Errorf("ServiceName(%d) = %q, want %q", tt.id, got, tt.want)
		}
	}
}

func TestDecoderSupports(t *testing.T) {
	dec := NewDecoder()
	// TCP port 4840 — should support.
	state := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 4840), time.Now())
	if !dec.Supports(state) {
		t.Fatal("expected Supports=true for TCP port 4840")
	}
	// UDP port 4840 — should NOT support.
	udpKey := flow.Key{
		SrcIP:   state.Key.SrcIP,
		DstIP:   state.Key.DstIP,
		SrcPort: 12345,
		DstPort: 4840,
		Proto:   17,
		Dir:     flow.DirForward,
	}
	udpState := flow.NewState(udpKey, time.Now())
	if dec.Supports(udpState) {
		t.Fatal("expected Supports=false for UDP")
	}
	// TCP different port — should NOT support.
	otherState := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 80), time.Now())
	if dec.Supports(otherState) {
		t.Fatal("expected Supports=false for port 80")
	}
}

func TestDecoderEmitsSessionEvent(t *testing.T) {
	dec := NewDecoder()
	state := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 4840), time.Now())
	raw := make([]byte, 32)
	copy(raw[0:3], "HEL")
	raw[3] = 'F'
	binary.LittleEndian.PutUint32(raw[4:8], 32)

	events, err := dec.OnPacket(state, &dpi.ParsedPacket{Payload: raw})
	if err != nil {
		t.Fatalf("onpacket: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Proto != "opcua" {
		t.Fatalf("unexpected proto: %s", ev.Proto)
	}
	if ev.Kind != "session" {
		t.Fatalf("unexpected kind: %s, expected session", ev.Kind)
	}
	if ev.Attributes["message_type"] != "HEL" {
		t.Fatalf("unexpected message_type: %v", ev.Attributes["message_type"])
	}
}

func TestDecoderEmitsMSGRequestEvent(t *testing.T) {
	dec := NewDecoder()
	state := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 4840), time.Now())
	raw := make([]byte, 28)
	copy(raw[0:3], "MSG")
	raw[3] = 'F'
	binary.LittleEndian.PutUint32(raw[4:8], 28)
	raw[24] = 0x01
	raw[25] = 0x00
	binary.LittleEndian.PutUint16(raw[26:28], ServiceReadRequest)

	events, err := dec.OnPacket(state, &dpi.ParsedPacket{Payload: raw})
	if err != nil {
		t.Fatalf("onpacket: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Kind != "request" {
		t.Fatalf("unexpected kind: %s", ev.Kind)
	}
	if ev.Attributes["service"] != "read-request" {
		t.Fatalf("unexpected service: %v", ev.Attributes["service"])
	}
	if ev.Attributes["is_write"] != false {
		t.Fatal("expected is_write=false for read-request")
	}
}

func TestDecoderEmitsMSGResponseEvent(t *testing.T) {
	dec := NewDecoder()
	state := flow.NewState(keyFor("10.0.0.2", "10.0.0.1", 4840, 12345), time.Now())
	raw := make([]byte, 28)
	copy(raw[0:3], "MSG")
	raw[3] = 'F'
	binary.LittleEndian.PutUint32(raw[4:8], 28)
	raw[24] = 0x01
	raw[25] = 0x00
	binary.LittleEndian.PutUint16(raw[26:28], ServiceWriteResponse)

	events, err := dec.OnPacket(state, &dpi.ParsedPacket{Payload: raw})
	if err != nil {
		t.Fatalf("onpacket: %v", err)
	}
	if len(events) != 1 || events[0].Kind != "response" {
		t.Fatalf("expected response event, got %+v", events)
	}
	if events[0].Attributes["is_write"] != true {
		t.Fatal("expected is_write=true for write-response")
	}
}

func TestDecoderNilPacket(t *testing.T) {
	dec := NewDecoder()
	state := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 12345, 4840), time.Now())
	events, err := dec.OnPacket(state, nil)
	if err != nil || len(events) != 0 {
		t.Fatal("expected no events for nil packet")
	}
}

func TestDecoderERREvent(t *testing.T) {
	dec := NewDecoder()
	state := flow.NewState(keyFor("10.0.0.2", "10.0.0.1", 4840, 12345), time.Now())
	raw := make([]byte, 16)
	copy(raw[0:3], "ERR")
	raw[3] = 'F'
	binary.LittleEndian.PutUint32(raw[4:8], 16)

	events, err := dec.OnPacket(state, &dpi.ParsedPacket{Payload: raw})
	if err != nil {
		t.Fatalf("onpacket: %v", err)
	}
	if len(events) != 1 || events[0].Kind != "response" {
		t.Fatalf("expected response event for ERR, got %+v", events)
	}
}
