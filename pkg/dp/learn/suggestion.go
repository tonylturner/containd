// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/evidence"
)

// SuggestionSchemaVersion versions immutable proposal content and proof encoding.
const SuggestionSchemaVersion = "1"

// SuggestionStatus is a persisted workflow state, never inferred from rule IDs.
type SuggestionStatus string

const (
	SuggestionDraft     SuggestionStatus = "draft"
	SuggestionCertified SuggestionStatus = "certified"
	SuggestionReviewed  SuggestionStatus = "reviewed"
	SuggestionStaged    SuggestionStatus = "staged"
	SuggestionRejected  SuggestionStatus = "rejected"
	SuggestionExpired   SuggestionStatus = "expired"
)

// Versions binds a proposal to all semantic inputs needed to reproduce its proof.
// These are compatibility fingerprints, not the appliance release version.
type Versions struct {
	Schema      string `json:"schema"`
	Observation string `json:"observation"`
	Generator   string `json:"generator"`
	Evaluator   string `json:"evaluator"`
	Decoder     string `json:"decoder"`
	Profile     string `json:"profile"`
	Snapshot    string `json:"snapshot"`
}

// SuggestionContent is immutable and content-addressed. Rules is a nonempty
// ordered atomic bundle (one element for a single rule), using canonical CP Rule
// JSON, not a parallel predicate model. Order is significant and must be stable.
// Every proposed rule is ALLOW with explicit ics.mode monitor, never inherited.
// EvidenceDigest hashes the complete ordered normalized parent set, not telemetry.
// Dataset/run IDs and workflow metadata are excluded from content identity.
type SuggestionContent struct {
	Versions                 Versions                  `json:"versions"`
	EvidenceDigest           string                    `json:"evidenceDigest"`
	Rules                    []config.Rule             `json:"rules"`
	Limits                   []string                  `json:"limits"`
	Withheld                 []evidence.WithheldReason `json:"withheld"`
	RequiresCoordinateReview bool                      `json:"requiresCoordinateReview"`
}

// ReplayTotals counts complete parent cases, not per-object matches. Positive
// cases must all pass; out-of-relation negatives must all be rejected. Zero
// positives/negatives cannot certify. Finite replay is not a universal proof.
type ReplayTotals struct {
	Total  uint64 `json:"total"`
	Passed uint64 `json:"passed"`
	Failed uint64 `json:"failed"`
}

// Counterexample records a reproducible pure-evaluator failure, never packets to
// send on a network. Mutation identifies the boundary and Parent the frozen input.
type Counterexample struct {
	Parent        evidence.EvidenceRef `json:"parent"`
	Mutation      string               `json:"mutation"`
	Expected      string               `json:"expected"`
	Actual        string               `json:"actual"`
	ContextDigest string               `json:"contextDigest"`
}

// Certification binds replay results to exact content and evidence/version bytes.
// ContentID commits to rule bytes, evidence digest and all Versions. ParentRefs
// must enumerate every positive input; unavailable evidence invalidates the proof.
type Certification struct {
	ContentID       string                 `json:"contentId"`
	EvidenceDigest  string                 `json:"evidenceDigest"`
	Versions        Versions               `json:"versions"`
	CertifiedAt     time.Time              `json:"certifiedAt"`
	ParentRefs      []evidence.EvidenceRef `json:"parentRefs"`
	Positive        ReplayTotals           `json:"positive"`
	Negative        ReplayTotals           `json:"negative"`
	Counterexamples []Counterexample       `json:"counterexamples"`
}

// LegacyOverlap is only a warning heuristic for existing learned-* rules. It
// never authorizes deletion, replacement or a prefix-based candidate mutation.
type LegacyOverlap struct {
	RuleID string `json:"ruleId"`
	Reason string `json:"reason"`
}

// Review is an authenticated backend acknowledgement of a specific revision.
// Coordinate approval acknowledges the shown wire/NAT scope; changing mapping
// creates new content and requires regeneration/certification, never an edit here.
type Review struct {
	Actor              string    `json:"actor"`
	At                 time.Time `json:"at"`
	Revision           uint64    `json:"revision"`
	CoordinateApproved bool      `json:"coordinateApproved"`
}

// Suggestion is a detached store value. Revision starts at 1 and increments on
// workflow transitions by compare-and-swap. Content never changes under an ID;
// new content gets a new ID. Evidence/proof expiry also invalidates prior review.
// IEC requires explicit admin review before staging; normal commit is separate.
type Suggestion struct {
	ID             string            `json:"id"`
	Revision       uint64            `json:"revision"`
	DatasetID      string            `json:"datasetId"`
	Content        SuggestionContent `json:"content"`
	Status         SuggestionStatus  `json:"status"`
	CreatedAt      time.Time         `json:"createdAt"`
	ExpiresAt      time.Time         `json:"expiresAt"`
	Proof          *Certification    `json:"proof,omitempty"`
	Review         *Review           `json:"review,omitempty"`
	LegacyOverlaps []LegacyOverlap   `json:"legacyOverlaps"`
}

// Selection identifies immutable server-owned content at an expected revision.
// Apply/review never accepts caller-supplied rules or a request to regenerate.
type Selection struct {
	ID       string `json:"id"`
	Revision uint64 `json:"revision"`
}

// ReviewRequest is an explicit review/reject action; Actor comes from auth, not
// JSON. The backend stamps time and verifies certification and coordinate scope.
type ReviewRequest struct {
	Selection          Selection `json:"selection"`
	Approve            bool      `json:"approve"`
	CoordinateApproved bool      `json:"coordinateApproved"`
}

// ApplyRequest replaces bulk learner apply with atomic selected staging only.
// RequestID is a caller-generated idempotency key; it never means commit/promote.
type ApplyRequest struct {
	RequestID  string      `json:"requestId"`
	Selections []Selection `json:"selections"`
}
