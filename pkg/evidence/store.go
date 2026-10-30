// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"context"
	"time"
)

// WithheldReason is a stable machine-readable reason, not a translated message.
// Observation-only data is still retained; no reason permits a broader fallback.
type WithheldReason string

const (
	WithheldIncomplete       WithheldReason = "incomplete_parent"
	WithheldMalformed        WithheldReason = "malformed"
	WithheldUndecoded        WithheldReason = "undecoded"
	WithheldMissingAuthority WithheldReason = "missing_authority"
	WithheldMissingSelector  WithheldReason = "missing_selector"
	WithheldNonstandardPort  WithheldReason = "nonstandard_port"
	WithheldCIP              WithheldReason = "cip_observation_only"
	WithheldModbusFC23       WithheldReason = "modbus_fc23_roles"
	WithheldModbusValues     WithheldReason = "modbus_write_values_or_masks"
	WithheldModbusSubtype    WithheldReason = "modbus_unbound_subtype"
	WithheldDNP3AllObjects   WithheldReason = "dnp3_all_objects"
	WithheldDNP3CountOnly    WithheldReason = "dnp3_count_only"
	WithheldDNP3Variation    WithheldReason = "dnp3_variation_wildcard"
	WithheldDNP3Indexless    WithheldReason = "dnp3_indexless_control"
	WithheldDNP3Values       WithheldReason = "dnp3_values"
	WithheldCorrelation      WithheldReason = "unrepresentable_correlation"
	WithheldIECQualifier     WithheldReason = "iec104_qualifier"
	WithheldIECValue         WithheldReason = "iec104_value"
	WithheldIECSBO           WithheldReason = "iec104_sbo_sequence"
	WithheldIECNonCommand    WithheldReason = "iec104_non_command"
	WithheldIECBroadcast     WithheldReason = "iec104_broadcast_ca"
	WithheldUnsupported      WithheldReason = "unsupported_operation"
	WithheldCoordinates      WithheldReason = "unsupported_coordinates"
	WithheldBudget           WithheldReason = "budget_exceeded"
	WithheldExpired          WithheldReason = "evidence_expired"
	WithheldReplay           WithheldReason = "replay_failed"
)

// Budgets are hard admission limits, never permissions to truncate a parent.
// Byte limits count canonical stored JSON, plus a separate physical DB ceiling.
type Budgets struct {
	MaxBytes         uint64 `json:"maxBytes"`
	MaxRecords       uint64 `json:"maxRecords"`
	MaxDatasets      uint64 `json:"maxDatasets"`
	MaxParentBytes   uint64 `json:"maxParentBytes"`
	MaxParentObjects uint32 `json:"maxParentObjects"`
}

// Counters are persisted cumulative loss/admission counters, not reset on GET.
// Evicting evidence invalidates dependent proofs, never silently shrinks a proof.
type Counters struct {
	Records         uint64                    `json:"records"`
	Bytes           uint64                    `json:"bytes"`
	EvictedRecords  uint64                    `json:"evictedRecords"`
	EvictedBytes    uint64                    `json:"evictedBytes"`
	ExpiredRecords  uint64                    `json:"expiredRecords"`
	LostBatches     uint64                    `json:"lostBatches"`
	RejectedParents uint64                    `json:"rejectedParents"`
	Withheld        map[WithheldReason]uint64 `json:"withheld"`
}

// IngestRequest is one bounded atomic batch of complete parents for a single
// dataset. For PCAP, Seal publishes the import atomically, including empty files.
// The store assigns ingestion timestamps, IDs/digests and enforces source/schema.
type IngestRequest struct {
	DatasetID string        `json:"datasetId"`
	Parents   []Observation `json:"parents"`
	Seal      bool          `json:"seal"`
	// Gaps retains capture/queue loss that cannot be attributed to a parent.
	// Codes are bounded metadata, never packet payloads or free-form logs.
	Gaps        []string `json:"gaps,omitempty"`
	LostBatches uint64   `json:"lostBatches,omitempty"`
	// CollectedAt is the trusted worker lease boundary, not capture input.
	// Only in-process collectors can supply it; it is never decoded from JSON.
	CollectedAt time.Time `json:"-"`
}

// IngestResult exposes admission loss, including an entire rejected parent.
type IngestResult struct {
	Accepted   uint64                    `json:"accepted"`
	Duplicates uint64                    `json:"duplicates"`
	Rejected   uint64                    `json:"rejected"`
	Reasons    map[WithheldReason]uint64 `json:"reasons"`
}

// Ingestor is the only normalized write path for live and PCAP adapters. It
// returns an error on storage failure; no asynchronous fire-and-forget success.
type Ingestor interface {
	Ingest(context.Context, IngestRequest) (IngestResult, error)
}

// PageRequest is bounded by the store (maximum 200); Cursor is opaque/keyset-based.
type PageRequest struct {
	Cursor string `json:"cursor,omitempty"`
	Limit  int    `json:"limit"`
}

// DatasetPage returns a stable bounded listing, without performing collection.
type DatasetPage struct {
	Items      []Dataset `json:"items"`
	NextCursor string    `json:"nextCursor,omitempty"`
}

// ObservationPage preserves parent boundaries and explicit pagination.
type ObservationPage struct {
	Items      []Observation `json:"items"`
	NextCursor string        `json:"nextCursor,omitempty"`
}

// WatchPage lists explicit leases, including stopped watches retained to expiry.
type WatchPage struct {
	Items      []Watch `json:"items"`
	NextCursor string  `json:"nextCursor,omitempty"`
}

// Store is owned by one engine process. Implementations return detached values.
// Import metadata is created before Ingest; PCAP datasets are invisible until
// sealed and Seal forbids further ingestion. No GET extends a TTL or starts work.
// Restart recovery seals interrupted imports as gapped and stops live watches.
// DeleteDataset invalidates dependent suggestions in the same local transaction.
type Store interface {
	Ingestor
	CreateDataset(context.Context, Dataset) (Dataset, error)
	StartWatch(context.Context, StartWatchRequest) (Watch, error)
	StopWatch(context.Context, string) (Watch, error)
	GetWatch(context.Context, string) (Watch, error)
	ListWatches(context.Context, PageRequest) (WatchPage, error)
	GetDataset(context.Context, string) (Dataset, error)
	ListDatasets(context.Context, PageRequest) (DatasetPage, error)
	ListObservations(context.Context, string, PageRequest) (ObservationPage, error)
	DeleteDataset(context.Context, string) error
	Counters(context.Context) (Counters, error)
	Close() error
}
