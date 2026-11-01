// SPDX-License-Identifier: Apache-2.0

// Package evidence defines the durable observation authority shared by learning,
// identification and baseline projections. It has no policy mutation dependency.
package evidence

import "time"

// SchemaVersion versions normalized records, not the firewall config schema.
const SchemaVersion = "1"

// Source identifies the adapter, never the trustworthiness of traffic.
type Source string

const (
	SourceLive Source = "live"
	SourcePCAP Source = "pcap"
)

// Coordinates identifies the address space used by ServiceKey.
type Coordinates string

const (
	CoordinatesLogical Coordinates = "logical"
	CoordinatesWire    Coordinates = "wire"
)

// Endpoint retains a directional transport endpoint, including ephemeral ports.
type Endpoint struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port"`
}

// Tuple is directional wire or verified logical/NAT transport evidence.
type Tuple struct {
	Source      Endpoint `json:"source"`
	Destination Endpoint `json:"destination"`
	Transport   string   `json:"transport"` // tcp|udp
}

// WireAliases retains both verified conntrack faces, not a synthesized reverse.
// The pair is immutable and bounded independently of connection lifetime.
type WireAliases struct {
	Original Tuple `json:"original"`
	Reply    Tuple `json:"reply"`
}

// ServiceKey is the policy relation key. Client source port is deliberately absent.
// Direction is request|response, from decoder/session authority, not port guessing.
type ServiceKey struct {
	ClientIP    string      `json:"clientIp"`
	ServerIP    string      `json:"serverIp"`
	ServerPort  uint16      `json:"serverPort"`
	Transport   string      `json:"transport"`
	Direction   string      `json:"direction"`
	Protocol    string      `json:"protocol"` // modbus|dnp3|iec104|cip
	Coordinates Coordinates `json:"coordinates"`
}

// Authority records why coordinates and roles may be used. Logical is absent
// without verified connection authority; PCAP never silently acquires NAT truth.
type Authority struct {
	Wire               Tuple        `json:"wire"`
	Logical            *Tuple       `json:"logical,omitempty"`
	Aliases            *WireAliases `json:"aliases,omitempty"`
	Correlation        string       `json:"correlation"` // verified|wire|unavailable
	RoleCertain        bool         `json:"roleCertain"`
	RoleEvidence       string       `json:"roleEvidence"`
	MappingFingerprint string       `json:"mappingFingerprint,omitempty"`
	StandardPort       bool         `json:"standardPort"`
}

// EvidenceRef locates original evidence without embedding packet payloads.
// Packet indexes are one-based; byte offsets are zero-based within the capture.
// Live refs instead name run/connection/parent; optional numbers retain zero.
type EvidenceRef struct {
	DatasetID     string  `json:"datasetId"`
	ObservationID string  `json:"observationId"`
	CaptureSHA256 string  `json:"captureSha256,omitempty"`
	PacketFirst   *uint64 `json:"packetFirst,omitempty"`
	PacketLast    *uint64 `json:"packetLast,omitempty"`
	ByteOffset    *uint64 `json:"byteOffset,omitempty"`
	ByteLength    *uint64 `json:"byteLength,omitempty"`
	RunID         string  `json:"runId,omitempty"`
}

// Quality preserves missing coverage rather than defaulting it to a safe decode.
// Complete means the entire parent and all declared children were captured.
type Quality struct {
	Complete    bool     `json:"complete"`
	Decoded     bool     `json:"decoded"`
	Conformance []string `json:"conformance"`
	Undecoded   []string `json:"undecoded"`
	Loss        []string `json:"loss"`
}

// Outcome distinguishes observed decisions from proven delivery. Unknown delivery
// must not be inferred from an ALLOW, a passive capture or a shadow match.
type Outcome struct {
	Decisions []Decision    `json:"decisions"`
	Delivery  string        `json:"delivery"` // unknown|delivered|blocked
	Evidence  []EvidenceRef `json:"evidence"`
}

// Decision preserves rule/scope attribution independently of delivery.
type Decision struct {
	Decision string `json:"decision"` // allow|deny|would_allow|would_drop
	Mode     string `json:"mode"`
	RuleID   string `json:"ruleId,omitempty"`
	ScopeID  string `json:"scopeId,omitempty"`
	Reason   string `json:"reason"`
}

// Observation is one immutable normalized parent message with ordered children.
// Ingest a whole parent atomically, never an independently truncated child walk.
// ID deduplicates dataset+connection incarnation+parent, not merely the five tuple.
// CapturedAt is original capture time; IngestedAt is assigned by the store clock.
// Fingerprints bind replay to the decoder/profile and policy snapshot used then.
// Pointer selectors in protocol records preserve absent versus explicit zero/false.
type Observation struct {
	SchemaVersion       string        `json:"schemaVersion"`
	ID                  string        `json:"id"`
	DatasetID           string        `json:"datasetId"`
	Source              Source        `json:"source"`
	CapturedAt          time.Time     `json:"capturedAt"`
	IngestedAt          time.Time     `json:"ingestedAt"`
	ConnectionID        string        `json:"connectionId"`
	ParentID            string        `json:"parentId"`
	ParentDigest        string        `json:"parentDigest"` // SHA-256 of canonical decoded parent
	ObjectCount         uint32        `json:"objectCount"`
	Authority           Authority     `json:"authority"`
	Service             ServiceKey    `json:"service"`
	DecoderVersion      string        `json:"decoderVersion"`
	ProfileFingerprint  string        `json:"profileFingerprint"`
	SnapshotFingerprint string        `json:"snapshotFingerprint"`
	Quality             Quality       `json:"quality"`
	Modbus              *Modbus       `json:"modbus,omitempty"`
	DNP3                *DNP3         `json:"dnp3,omitempty"`
	IEC104              *IEC104       `json:"iec104,omitempty"`
	CIP                 *CIP          `json:"cip,omitempty"`
	Outcome             Outcome       `json:"outcome"`
	Evidence            []EvidenceRef `json:"evidence"`
}
