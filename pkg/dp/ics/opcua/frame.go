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

// Known service node IDs for MSG requests.
const (
	ServiceReadRequest               = 631
	ServiceReadResponse              = 634
	ServiceWriteRequest              = 673
	ServiceWriteResponse             = 676
	ServiceBrowseRequest             = 527
	ServiceBrowseResponse            = 530
	ServiceCreateSubscriptionRequest = 787
	ServiceCreateSubscriptionResponse = 790
	ServicePublishRequest            = 826
	ServicePublishResponse           = 829
	ServiceCallRequest               = 712
	ServiceCallResponse              = 715
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

// ServiceName returns a human-readable name for a known OPC UA service node ID.
func ServiceName(nodeID uint16) string {
	switch nodeID {
	case ServiceReadRequest:
		return "read-request"
	case ServiceReadResponse:
		return "read-response"
	case ServiceWriteRequest:
		return "write-request"
	case ServiceWriteResponse:
		return "write-response"
	case ServiceBrowseRequest:
		return "browse-request"
	case ServiceBrowseResponse:
		return "browse-response"
	case ServiceCreateSubscriptionRequest:
		return "create-subscription-request"
	case ServiceCreateSubscriptionResponse:
		return "create-subscription-response"
	case ServicePublishRequest:
		return "publish-request"
	case ServicePublishResponse:
		return "publish-response"
	case ServiceCallRequest:
		return "call-request"
	case ServiceCallResponse:
		return "call-response"
	default:
		return fmt.Sprintf("service-%d", nodeID)
	}
}

// IsWriteService returns true for OPC UA services that mutate state.
func IsWriteService(nodeID uint16) bool {
	switch nodeID {
	case ServiceWriteRequest, ServiceWriteResponse,
		ServiceCallRequest, ServiceCallResponse:
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
