// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"context"
	"errors"

	"github.com/tonylturner/containd/pkg/evidence"
)

var (
	// ErrStale means content/revision, proof versions or candidate state changed.
	ErrStale = errors.New("stale suggestion")
	// ErrExpired means evidence or its reproducible proof is no longer available.
	ErrExpired = errors.New("suggestion evidence expired")
	// ErrNotCertified prevents draft/failed proof from reaching candidate staging.
	ErrNotCertified = errors.New("suggestion is not certified")
	// ErrReviewRequired prevents IEC or wire-coordinate staging without review.
	ErrReviewRequired = errors.New("explicit suggestion review required")
)

// GenerateRequest selects a sealed immutable dataset, not a moving live window.
type GenerateRequest struct {
	DatasetID string `json:"datasetId"`
}

// GenerateResult includes withheld counts even when no actionable rules exist.
type GenerateResult struct {
	Suggestions []Selection                        `json:"suggestions"`
	Withheld    map[evidence.WithheldReason]uint64 `json:"withheld"`
}

// SuggestionPage is bounded and supports view-only inspection without generation.
type SuggestionPage struct {
	Items      []Suggestion `json:"items"`
	NextCursor string       `json:"nextCursor,omitempty"`
}

// Certifier performs only in-memory replay through the real CP compiler and DP
// evaluator/context projector. It has no raw replay, network or config mutation
// dependency. It reloads all immutable parents from evidence, checks versions and
// returns counterexamples/withheld reasons on failure; no evidence means no proof.
// Certification results are persisted only by the trusted generator/store owner.
type Certifier interface {
	Certify(context.Context, SuggestionContent, []evidence.EvidenceRef) (Certification, error)
}

// SuggestionStore extends the same evidence authority, not a second database.
// PutDraft is create-only; SaveCertification validates proof binding and CAS.
// ResolveForStage checks ALL selections in one transaction, binds RequestID to
// their immutable revisions for retries, and returns
// detached immutable content or one error, never a partially resolved batch.
// It rejects expired/uncertified/rejected entries, unreviewed IEC and missing
// coordinate approval. Management atomically mutates config.Store's candidate
// using only these returned rules, never sends arbitrary rule JSON back here.
// MarkStaged is idempotent by RequestID; a crash after candidate save must be
// reconciled against the identical candidate rules, not treated as an activation.
type SuggestionStore interface {
	evidence.Store
	PutDraft(context.Context, Suggestion) (Suggestion, error)
	SaveCertification(context.Context, Selection, Certification) (Suggestion, error)
	// SaveReplayFailure retains bounded counterexamples without certifying a draft.
	SaveReplayFailure(context.Context, Selection, Certification) (Suggestion, error)
	GetSuggestion(context.Context, string) (Suggestion, error)
	ListSuggestions(context.Context, string, evidence.PageRequest) (SuggestionPage, error)
	ReviewSuggestion(context.Context, string, ReviewRequest) (Suggestion, error)
	ResolveForStage(context.Context, ApplyRequest) ([]Suggestion, error)
	MarkStaged(context.Context, ApplyRequest) error
}

// Service is the engine-internal orchestration interface called by management.
// Generate explicitly writes drafts/proofs; all read operations stay on Store.
// A running watch must first be stopped/sealed. No method stages or commits policy.
type Service interface {
	Generate(context.Context, GenerateRequest) (GenerateResult, error)
}
