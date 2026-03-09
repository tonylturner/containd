// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package opcua

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// OPC UA message types (3-byte ASCII).
const (
	MsgTypeHEL = "HEL"
	MsgTypeACK = "ACK"
	MsgTypeOPN = "OPN"
	MsgTypeCLO = "CLO"
	MsgTypeMSG = "MSG"
	MsgTypeERR = "ERR"
)

// Chunk types.
const (
	ChunkFinal        = 'F'
	ChunkIntermediate = 'C'
	ChunkAbort        = 'A'
)

// Known service node IDs for MSG requests and responses.
const (
	// Attribute services
	ServiceReadRequest    = 629
	ServiceReadResponse   = 632
	ServiceWriteRequest   = 671
	ServiceWriteResponse  = 674
	ServiceHistoryReadRequest  = 673
	ServiceHistoryReadResponse = 676
	ServiceHistoryUpdateRequest  = 700
	ServiceHistoryUpdateResponse = 703

	// View services
	ServiceBrowseRequest     = 525
	ServiceBrowseResponse    = 528
	ServiceBrowseNextRequest  = 531
	ServiceBrowseNextResponse = 534
	ServiceTranslateBrowsePathsRequest  = 554 // TranslateBrowsePathsToNodeIds is typically 554
	ServiceTranslateBrowsePathsResponse = 557

	// Session services
	ServiceCreateSessionRequest   = 459
	ServiceCreateSessionResponse  = 462
	ServiceActivateSessionRequest  = 465 // ActivateSession request
	ServiceActivateSessionResponse = 468
	ServiceCloseSessionRequest    = 471
	ServiceCloseSessionResponse   = 474

	// Node management
	ServiceAddNodesRequest       = 486
	ServiceAddNodesResponse      = 489
	ServiceDeleteNodesRequest    = 498
	ServiceDeleteNodesResponse   = 501
	ServiceAddReferencesRequest  = 502
	ServiceAddReferencesResponse = 505
	ServiceDeleteReferencesRequest  = 506
	ServiceDeleteReferencesResponse = 509

	// Method
	ServiceCallRequest  = 710
	ServiceCallResponse = 713

	// Subscription services
	ServiceCreateSubscriptionRequest  = 785
	ServiceCreateSubscriptionResponse = 788
	ServiceModifySubscriptionRequest  = 793
	ServiceModifySubscriptionResponse = 796
	ServiceDeleteSubscriptionsRequest  = 799
	ServiceDeleteSubscriptionsResponse = 802
	ServicePublishRequest  = 826
	ServicePublishResponse = 829

	// MonitoredItem services
	ServiceCreateMonitoredItemsRequest  = 749
	ServiceCreateMonitoredItemsResponse = 752
	ServiceModifyMonitoredItemsRequest  = 761
	ServiceModifyMonitoredItemsResponse = 764
	ServiceDeleteMonitoredItemsRequest  = 779
	ServiceDeleteMonitoredItemsResponse = 782
)

var (
	ErrTooShort      = errors.New("opcua message too short")
	ErrInvalidMsgType = errors.New("opcua invalid message type")
)

// Frame represents a parsed OPC UA Binary message header.
type Frame struct {
	MessageType string // 3-byte ASCII: HEL, ACK, OPN, CLO, MSG, ERR
	ChunkType   byte   // 'F', 'C', 'A'
	MessageSize uint32

	// ServiceNodeID is only populated for MSG messages when identifiable.
	// It is the numeric node ID from the request/response encoding.
	ServiceNodeID uint16
	HasService    bool
}

// ParseFrame parses an OPC UA Binary message header from raw TCP payload bytes.
func ParseFrame(b []byte) (*Frame, error) {
	if len(b) < 8 {
		return nil, ErrTooShort
	}

	msgType := string(b[0:3])
	if !isValidMsgType(msgType) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidMsgType, msgType)
	}

	f := &Frame{
		MessageType: msgType,
		ChunkType:   b[3],
		MessageSize: binary.LittleEndian.Uint32(b[4:8]),
	}

	// For MSG type, attempt to extract service node ID.
	// OPC UA MSG layout after the 8-byte header:
	//   SecureChannelId (4 bytes)
	//   SecurityTokenId (4 bytes)
	//   SecuritySequenceNumber (4 bytes)
	//   SecurityRequestId (4 bytes)
	//   NodeId encoding (variable)
	// Minimum offset for node ID: 8 + 16 = 24
	if msgType == MsgTypeMSG && len(b) >= 26 {
		nodeOffset := 24
		f.ServiceNodeID, f.HasService = parseNodeID(b[nodeOffset:])
	}

	return f, nil
}

// parseNodeID attempts to parse a UA Binary NodeId at the start of b.
// Returns the numeric identifier and true if successful.
func parseNodeID(b []byte) (uint16, bool) {
	if len(b) < 1 {
		return 0, false
	}

	encodingByte := b[0]
	switch encodingByte & 0x0F {
	case 0x00:
		// Two-byte node ID: encoding(1) + id(1)
		if len(b) < 2 {
			return 0, false
		}
		return uint16(b[1]), true
	case 0x01:
		// Four-byte node ID: encoding(1) + namespace(1) + id(2)
		if len(b) < 4 {
			return 0, false
		}
		return binary.LittleEndian.Uint16(b[2:4]), true
	case 0x02:
		// Numeric node ID: encoding(1) + namespace(2) + id(4)
		if len(b) < 7 {
			return 0, false
		}
		id := binary.LittleEndian.Uint32(b[3:7])
		if id > 0xFFFF {
			return 0, false
		}
		return uint16(id), true
	default:
		// String, GUID, or opaque node IDs — not decoded.
		return 0, false
	}
}

func isValidMsgType(s string) bool {
	switch s {
	case MsgTypeHEL, MsgTypeACK, MsgTypeOPN, MsgTypeCLO, MsgTypeMSG, MsgTypeERR:
		return true
	default:
		return false
	}
}

// serviceNameMap maps OPC UA service node IDs to human-readable names.
// Using a map avoids a long switch in the hot path while keeping O(1) lookup.
var serviceNameMap = map[uint16]string{
	ServiceReadRequest:    "read-request",
	ServiceReadResponse:   "read-response",
	ServiceWriteRequest:   "write-request",
	ServiceWriteResponse:  "write-response",
	ServiceHistoryReadRequest:  "history-read-request",
	ServiceHistoryReadResponse: "history-read-response",
	ServiceHistoryUpdateRequest:  "history-update-request",
	ServiceHistoryUpdateResponse: "history-update-response",
	ServiceBrowseRequest:     "browse-request",
	ServiceBrowseResponse:    "browse-response",
	ServiceBrowseNextRequest:  "browse-next-request",
	ServiceBrowseNextResponse: "browse-next-response",
	ServiceTranslateBrowsePathsRequest:  "translate-browse-paths-request",
	ServiceTranslateBrowsePathsResponse: "translate-browse-paths-response",
	ServiceCreateSessionRequest:   "create-session-request",
	ServiceCreateSessionResponse:  "create-session-response",
	ServiceActivateSessionRequest:  "activate-session-request",
	ServiceActivateSessionResponse: "activate-session-response",
	ServiceCloseSessionRequest:    "close-session-request",
	ServiceCloseSessionResponse:   "close-session-response",
	ServiceAddNodesRequest:       "add-nodes-request",
	ServiceAddNodesResponse:      "add-nodes-response",
	ServiceDeleteNodesRequest:    "delete-nodes-request",
	ServiceDeleteNodesResponse:   "delete-nodes-response",
	ServiceAddReferencesRequest:  "add-references-request",
	ServiceAddReferencesResponse: "add-references-response",
	ServiceDeleteReferencesRequest:  "delete-references-request",
	ServiceDeleteReferencesResponse: "delete-references-response",
	ServiceCallRequest:  "call-request",
	ServiceCallResponse: "call-response",
	ServiceCreateSubscriptionRequest:  "create-subscription-request",
	ServiceCreateSubscriptionResponse: "create-subscription-response",
	ServiceModifySubscriptionRequest:  "modify-subscription-request",
	ServiceModifySubscriptionResponse: "modify-subscription-response",
	ServiceDeleteSubscriptionsRequest:  "delete-subscriptions-request",
	ServiceDeleteSubscriptionsResponse: "delete-subscriptions-response",
	ServicePublishRequest:  "publish-request",
	ServicePublishResponse: "publish-response",
	ServiceCreateMonitoredItemsRequest:  "create-monitored-items-request",
	ServiceCreateMonitoredItemsResponse: "create-monitored-items-response",
	ServiceModifyMonitoredItemsRequest:  "modify-monitored-items-request",
	ServiceModifyMonitoredItemsResponse: "modify-monitored-items-response",
	ServiceDeleteMonitoredItemsRequest:  "delete-monitored-items-request",
	ServiceDeleteMonitoredItemsResponse: "delete-monitored-items-response",
}

// ServiceName returns a human-readable name for a known OPC UA service node ID.
func ServiceName(nodeID uint16) string {
	if name, ok := serviceNameMap[nodeID]; ok {
		return name
	}
	return fmt.Sprintf("service-%d", nodeID)
}

// IsWriteService returns true for OPC UA services that mutate state.
func IsWriteService(nodeID uint16) bool {
	switch nodeID {
	case ServiceWriteRequest, ServiceWriteResponse,
		ServiceHistoryUpdateRequest, ServiceHistoryUpdateResponse,
		ServiceAddNodesRequest, ServiceAddNodesResponse,
		ServiceDeleteNodesRequest, ServiceDeleteNodesResponse,
		ServiceDeleteSubscriptionsRequest, ServiceDeleteSubscriptionsResponse,
		ServiceDeleteMonitoredItemsRequest, ServiceDeleteMonitoredItemsResponse,
		ServiceCallRequest, ServiceCallResponse:
		return true
	default:
		return false
	}
}

// IsResponseService returns true for OPC UA response service node IDs.
func IsResponseService(nodeID uint16) bool {
	switch nodeID {
	case ServiceReadResponse, ServiceWriteResponse,
		ServiceHistoryReadResponse, ServiceHistoryUpdateResponse,
		ServiceBrowseResponse, ServiceBrowseNextResponse,
		ServiceTranslateBrowsePathsResponse,
		ServiceCreateSessionResponse, ServiceActivateSessionResponse,
		ServiceCloseSessionResponse,
		ServiceAddNodesResponse, ServiceDeleteNodesResponse,
		ServiceAddReferencesResponse, ServiceDeleteReferencesResponse,
		ServiceCallResponse,
		ServiceCreateSubscriptionResponse, ServiceModifySubscriptionResponse,
		ServiceDeleteSubscriptionsResponse, ServicePublishResponse,
		ServiceCreateMonitoredItemsResponse, ServiceModifyMonitoredItemsResponse,
		ServiceDeleteMonitoredItemsResponse:
		return true
	default:
		return false
	}
}

// IsSessionMessage returns true for HEL/ACK/OPN/CLO message types.
func IsSessionMessage(msgType string) bool {
	switch msgType {
	case MsgTypeHEL, MsgTypeACK, MsgTypeOPN, MsgTypeCLO:
		return true
	default:
		return false
	}
}
