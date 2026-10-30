// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"fmt"
	"time"
)

const (
	// DefaultWatchDuration is used only by explicit StartWatch with no duration.
	DefaultWatchDuration = time.Hour
	// MaxWatchDuration prevents unbounded implicit live collection.
	MaxWatchDuration = 24 * time.Hour
	// Retention is bounded by store ingestion/creation time, never capture time.
	Retention = 7 * 24 * time.Hour
)

// DatasetState distinguishes a private import or live watch from sealed data.
type DatasetState string

const (
	DatasetImporting  DatasetState = "importing"
	DatasetCollecting DatasetState = "collecting"
	DatasetSealed     DatasetState = "sealed"
	DatasetExpired    DatasetState = "expired"
)

// Dataset is an evidence window. PCAP import seals atomically; no append/edit API
// exists for a sealed dataset. Expiry/eviction can remove it but cannot rewrite it.
// PCAP ID binds capture SHA + decoder/profile/snapshot fingerprints; live ID is
// assigned at explicit start. Incomplete retention is visible through Gaps.
type Dataset struct {
	SchemaVersion       string       `json:"schemaVersion"`
	ID                  string       `json:"id"`
	Source              Source       `json:"source"`
	State               DatasetState `json:"state"`
	CreatedAt           time.Time    `json:"createdAt"`
	SealedAt            *time.Time   `json:"sealedAt,omitempty"`
	ExpiresAt           time.Time    `json:"expiresAt"`
	CaptureSHA256       string       `json:"captureSha256,omitempty"`
	DecoderVersion      string       `json:"decoderVersion"`
	ProfileFingerprint  string       `json:"profileFingerprint"`
	SnapshotFingerprint string       `json:"snapshotFingerprint"`
	EvidenceDigest      string       `json:"evidenceDigest"`
	Records             uint64       `json:"records"`
	Bytes               uint64       `json:"bytes"`
	Gaps                []string     `json:"gaps"`
}

// Watch is an explicit live collection lease. A restart stops, never resumes it.
// DatasetID identifies the accumulating evidence; a stopped watch is immutable.
type Watch struct {
	ID         string     `json:"id"`
	DatasetID  string     `json:"datasetId"`
	StartedAt  time.Time  `json:"startedAt"`
	Deadline   time.Time  `json:"deadline"`
	StoppedAt  *time.Time `json:"stoppedAt,omitempty"`
	StopReason string     `json:"stopReason,omitempty"` // operator|deadline|restart|budget
}

// StartWatchRequest uses seconds on the wire rather than Go nanoseconds.
// A zero duration requests the default; negative/over-limit durations are errors.
type StartWatchRequest struct {
	DurationSeconds int64 `json:"durationSeconds"`
}

// Duration resolves a valid explicit start request without changing state.
func (r StartWatchRequest) Duration() (time.Duration, error) {
	if r.DurationSeconds == 0 {
		return DefaultWatchDuration, nil
	}
	if r.DurationSeconds < 0 || r.DurationSeconds > int64(MaxWatchDuration/time.Second) {
		return 0, fmt.Errorf("watch duration must be 1..%d seconds", int64(MaxWatchDuration/time.Second))
	}
	return time.Duration(r.DurationSeconds) * time.Second, nil
}
