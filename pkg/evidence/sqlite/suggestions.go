// SPDX-License-Identifier: Apache-2.0

package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"

	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/evidence"
)

func saveSuggestion(ctx context.Context, tx *sql.Tx, v learn.Suggestion) error {
	b, err := encode(v)
	if err != nil {
		return err
	}
	if len(b) > 256<<10 || len(v.Content.Rules) > 128 {
		return ErrBudget
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO suggestions VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET expires=excluded.expires,data=excluded.data`, v.ID, v.DatasetID, v.ExpiresAt.UnixNano(), b)
	return err
}

func (s *Store) updateSuggestion(ctx context.Context, tx *sql.Tx, v learn.Suggestion, protected []string) error {
	b, err := encode(v)
	if err != nil {
		return err
	}
	var prior uint64
	if err := tx.QueryRowContext(ctx, `SELECT length(data) FROM suggestions WHERE id=?`, v.ID).Scan(&prior); err != nil {
		return err
	}
	add := uint64(0)
	if uint64(len(b)) > prior {
		add = uint64(len(b)) - prior
	}
	if err := s.fitExcept(ctx, tx, protected, add, 0, 0); err != nil {
		return err
	}
	return saveSuggestion(ctx, tx, v)
}

func (s *Store) PutDraft(ctx context.Context, v learn.Suggestion) (learn.Suggestion, error) {
	id, err := v.Content.ContentID()
	if err != nil {
		return v, err
	}
	err = s.write(ctx, func(tx *sql.Tx) error {
		existing, err := read[learn.Suggestion](ctx, tx, `SELECT data FROM suggestions WHERE id=?`, id)
		if err == nil {
			v = existing
			return nil
		}
		if err != ErrNotFound {
			return err
		}
		d, err := read[evidence.Dataset](ctx, tx, `SELECT data FROM datasets WHERE id=?`, v.DatasetID)
		if err != nil {
			return err
		}
		if d.State != evidence.DatasetSealed {
			return ErrConflict
		}
		var total, perDataset int
		if err := tx.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(dataset=?),0) FROM suggestions`, d.ID).Scan(&total, &perDataset); err != nil {
			return err
		}
		if total >= 10000 || perDataset >= 2000 {
			return ErrBudget
		}
		v.ID, v.Revision, v.Status = id, 1, learn.SuggestionDraft
		v.CreatedAt, v.ExpiresAt, v.Proof, v.Review = s.now().UTC(), d.ExpiresAt, nil, nil
		b, err := encode(v)
		if err != nil {
			return err
		}
		if err := s.fit(ctx, tx, d.ID, uint64(len(b))+1024, 0, 0); err != nil {
			return err
		}
		return saveSuggestion(ctx, tx, v)
	})
	return v, err
}

func (s *Store) SaveCertification(ctx context.Context, selection learn.Selection, p learn.Certification) (learn.Suggestion, error) {
	return s.saveReplay(ctx, selection, p, true)
}
func (s *Store) SaveReplayFailure(ctx context.Context, selection learn.Selection, p learn.Certification) (learn.Suggestion, error) {
	return s.saveReplay(ctx, selection, p, false)
}
func (s *Store) saveReplay(ctx context.Context, selection learn.Selection, p learn.Certification, certified bool) (learn.Suggestion, error) {
	var v learn.Suggestion
	err := s.write(ctx, func(tx *sql.Tx) error {
		var err error
		v, err = s.suggestion(ctx, tx, selection.ID)
		if err != nil {
			return err
		}
		if selection.Revision == 0 || selection.Revision != v.Revision || v.Status != learn.SuggestionDraft {
			return learn.ErrStale
		}
		if certified {
			if err := p.ValidateBinding(v.Content); err != nil {
				return err
			}
		} else {
			if p.ContentID != v.ID || p.EvidenceDigest != v.Content.EvidenceDigest || p.Versions != v.Content.Versions || p.CertifiedAt.IsZero() || len(p.Counterexamples) == 0 || len(p.Counterexamples) > 50 || p.Positive.Failed+p.Negative.Failed == 0 {
				return learn.ErrNotCertified
			}
		}
		if !s.compatibleProof(p.Versions) {
			return learn.ErrStale
		}
		if len(p.ParentRefs) == 0 || len(p.ParentRefs) > 10000 || p.Positive.Passed+p.Positive.Failed != p.Positive.Total || p.Negative.Passed+p.Negative.Failed != p.Negative.Total || p.Positive.Total != uint64(len(p.ParentRefs)) || p.Negative.Total > 100000 {
			return ErrBudget
		}
		seen := map[string]bool{}
		parents := make([]evidence.Observation, 0, len(p.ParentRefs))
		for _, ref := range p.ParentRefs {
			if ref.DatasetID != v.DatasetID || seen[ref.ObservationID] {
				return learn.ErrNotCertified
			}
			seen[ref.ObservationID] = true
			o, err := read[evidence.Observation](ctx, tx, `SELECT data FROM parents WHERE id=? AND dataset=?`, ref.ObservationID, v.DatasetID)
			if err != nil {
				return err
			}
			parents = append(parents, o)
			parentExpiry := o.IngestedAt.Add(evidence.Retention)
			if parentExpiry.Before(v.ExpiresAt) {
				v.ExpiresAt = parentExpiry
			}
		}
		digest, err := evidence.EvidenceDigest(parents)
		if err != nil {
			return err
		}
		if digest != v.Content.EvidenceDigest {
			return learn.ErrNotCertified
		}
		v.Proof, v.Revision = &p, v.Revision+1
		if certified {
			v.Status = learn.SuggestionCertified
		}
		return s.updateSuggestion(ctx, tx, v, []string{v.DatasetID})
	})
	return v, err
}

func (s *Store) GetSuggestion(ctx context.Context, id string) (learn.Suggestion, error) {
	return s.suggestion(ctx, s.db, id)
}

func (s *Store) suggestion(ctx context.Context, db reader, id string) (learn.Suggestion, error) {
	v, err := read[learn.Suggestion](ctx, db, `SELECT data FROM suggestions WHERE id=?`, id)
	if err == ErrNotFound {
		err = s.missingFrom(ctx, db, id)
	}
	if err == nil && !s.now().Before(v.ExpiresAt) {
		err = learn.ErrExpired
	}
	return v, err
}

func (s *Store) ListSuggestions(ctx context.Context, dataset string, p evidence.PageRequest) (learn.SuggestionPage, error) {
	items, next, err := page[learn.Suggestion](ctx, s.db, `SELECT id,data FROM suggestions WHERE (?='' OR dataset=?) AND expires>? AND id>? ORDER BY id LIMIT ?`, []any{dataset, dataset, s.now().UnixNano()}, p)
	return learn.SuggestionPage{Items: items, NextCursor: next}, err
}

func (s *Store) ReviewSuggestion(ctx context.Context, actor string, req learn.ReviewRequest) (learn.Suggestion, error) {
	var v learn.Suggestion
	err := s.write(ctx, func(tx *sql.Tx) error {
		var err error
		v, err = s.suggestion(ctx, tx, req.Selection.ID)
		if err != nil {
			return err
		}
		if actor == "" || req.Selection.Revision == 0 || req.Selection.Revision != v.Revision || (v.Status != learn.SuggestionCertified && v.Status != learn.SuggestionReviewed) {
			return learn.ErrStale
		}
		var reserved int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM stage_selections WHERE suggestion=?`, v.ID).Scan(&reserved); err != nil {
			return err
		}
		if reserved != 0 {
			return learn.ErrStale
		}
		if v.Proof == nil {
			return learn.ErrNotCertified
		}
		if err := v.Proof.ValidateBinding(v.Content); err != nil {
			return err
		}
		if !s.compatibleProof(v.Proof.Versions) {
			return learn.ErrStale
		}
		v.Review = &learn.Review{Actor: actor, At: s.now().UTC(), Revision: v.Revision, CoordinateApproved: req.CoordinateApproved}
		v.Status = learn.SuggestionRejected
		if req.Approve {
			v.Status = learn.SuggestionReviewed
		}
		v.Revision++
		return s.updateSuggestion(ctx, tx, v, []string{v.DatasetID})
	})
	return v, err
}

// ValidateApply rejects ambiguous selections before touching either authority.
func ValidateApply(req learn.ApplyRequest) error {
	if req.RequestID == "" || len(req.RequestID) > 128 || len(req.Selections) == 0 || len(req.Selections) > 128 {
		return ErrConflict
	}
	seen := map[string]bool{}
	for _, selection := range req.Selections {
		if selection.ID == "" || selection.Revision == 0 || seen[selection.ID] {
			return ErrConflict
		}
		seen[selection.ID] = true
	}
	return nil
}

func (s *Store) ResolveForStage(ctx context.Context, req learn.ApplyRequest) ([]learn.Suggestion, error) {
	if err := ValidateApply(req); err != nil {
		return nil, err
	}
	request, err := encode(req)
	if err != nil {
		return nil, err
	}
	var out []learn.Suggestion
	err = s.write(ctx, func(tx *sql.Tx) error {
		var prior, resolved []byte
		err := tx.QueryRowContext(ctx, `SELECT request,resolved FROM stage_requests WHERE id=?`, req.RequestID).Scan(&prior, &resolved)
		if err == nil {
			if !bytes.Equal(prior, request) {
				return learn.ErrStale
			}
			if err := json.Unmarshal(resolved, &out); err != nil {
				return err
			}
			// A reservation does not restore deleted/expired evidence.
			for _, v := range out {
				if !s.now().Before(v.ExpiresAt) {
					return learn.ErrExpired
				}
				if _, err := s.suggestion(ctx, tx, v.ID); err != nil {
					return err
				}
				if v.Proof == nil || !s.compatibleProof(v.Proof.Versions) {
					return learn.ErrStale
				}
			}
			return nil
		}
		if err != sql.ErrNoRows {
			return err
		}
		expires := s.now().Add(evidence.Retention)
		rules := 0
		for _, selection := range req.Selections {
			v, err := s.suggestion(ctx, tx, selection.ID)
			if err != nil {
				return err
			}
			if !s.now().Before(v.ExpiresAt) {
				return learn.ErrExpired
			}
			if selection.Revision != v.Revision || (v.Status != learn.SuggestionCertified && v.Status != learn.SuggestionReviewed) {
				return learn.ErrStale
			}
			var reserved int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM stage_selections WHERE suggestion=?`, v.ID).Scan(&reserved); err != nil {
				return err
			}
			if reserved != 0 {
				return learn.ErrStale
			}
			if v.Proof == nil {
				return learn.ErrNotCertified
			}
			if err := v.Proof.ValidateBinding(v.Content); err != nil {
				return err
			}
			if !s.compatibleProof(v.Proof.Versions) {
				return learn.ErrStale
			}
			needsReview := false
			for _, r := range v.Content.Rules {
				needsReview = needsReview || r.ICS.Protocol == "iec104"
			}
			if needsReview && v.Status != learn.SuggestionReviewed || v.Content.RequiresCoordinateReview && (v.Review == nil || !v.Review.CoordinateApproved) {
				return learn.ErrReviewRequired
			}
			rules += len(v.Content.Rules)
			if rules > 128 {
				return ErrBudget
			}
			if v.ExpiresAt.Before(expires) {
				expires = v.ExpiresAt
			}
			out = append(out, v)
		}
		resolved, err = encode(out)
		if err != nil {
			return err
		}
		if len(resolved)+len(request) > maxBatch {
			return ErrBudget
		}
		protected := make([]string, 0, len(out))
		add := uint64(len(resolved) + len(request))
		for _, v := range out {
			protected = append(protected, v.DatasetID)
			add += uint64(len(req.RequestID) + len(v.ID))
		}
		if err := s.fitExcept(ctx, tx, protected, add, 0, 0); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO stage_requests(id,expires,request,resolved) VALUES(?,?,?,?)`, req.RequestID, expires.UnixNano(), request, resolved)
		if err != nil {
			return err
		}
		for _, selection := range req.Selections {
			if _, err := tx.ExecContext(ctx, `INSERT INTO stage_selections VALUES(?,?)`, req.RequestID, selection.ID); err != nil {
				return err
			}
		}
		return nil
	})
	return out, err
}

func (s *Store) invalidateProofs(ctx context.Context, tx *sql.Tx) error {
	p := evidence.PageRequest{Limit: 200}
	for {
		values, next, err := page[learn.Suggestion](ctx, tx, `SELECT id,data FROM suggestions WHERE id>? ORDER BY id LIMIT ?`, nil, p)
		if err != nil {
			return err
		}
		for _, v := range values {
			if v.Proof == nil || s.compatibleProof(v.Proof.Versions) {
				continue
			}
			v.Status, v.Proof, v.Review, v.Revision = learn.SuggestionExpired, nil, nil, v.Revision+1
			if err := saveSuggestion(ctx, tx, v); err != nil {
				return err
			}
		}
		if next == "" {
			return nil
		}
		p.Cursor = next
	}
}

func (s *Store) MarkStaged(ctx context.Context, req learn.ApplyRequest) error {
	if err := ValidateApply(req); err != nil {
		return err
	}
	b, err := encode(req)
	if err != nil {
		return err
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		var prior, resolved []byte
		var completed bool
		if err := tx.QueryRowContext(ctx, `SELECT request,resolved,completed FROM stage_requests WHERE id=?`, req.RequestID).Scan(&prior, &resolved, &completed); err != nil {
			if err == sql.ErrNoRows {
				return ErrNotFound
			}
			return err
		}
		if !bytes.Equal(prior, b) {
			return learn.ErrStale
		}
		if completed {
			return nil
		}
		var values []learn.Suggestion
		if err := json.Unmarshal(resolved, &values); err != nil {
			return err
		}
		protected := make([]string, 0, len(values))
		for _, v := range values {
			protected = append(protected, v.DatasetID)
		}
		for _, v := range values {
			current, err := s.suggestion(ctx, tx, v.ID)
			if err != nil {
				return err
			}
			if current.Revision != v.Revision {
				return learn.ErrStale
			}
			current.Status, current.Revision = learn.SuggestionStaged, current.Revision+1
			if err := s.updateSuggestion(ctx, tx, current, protected); err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(ctx, `UPDATE stage_requests SET completed=1 WHERE id=?`, req.RequestID)
		return err
	})
}

// ReleaseStage releases only a known failed candidate mutation. Lost completion
// after a successful mutation must instead retry the frozen request.
func (s *Store) ReleaseStage(ctx context.Context, req learn.ApplyRequest) error {
	if err := ValidateApply(req); err != nil {
		return err
	}
	b, err := encode(req)
	if err != nil {
		return err
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		var prior []byte
		var completed bool
		err := tx.QueryRowContext(ctx, `SELECT request,completed FROM stage_requests WHERE id=?`, req.RequestID).Scan(&prior, &completed)
		if err == sql.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}
		if !bytes.Equal(prior, b) {
			return learn.ErrStale
		}
		if completed {
			return nil
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM stage_requests WHERE id=?`, req.RequestID)
		return err
	})
}
