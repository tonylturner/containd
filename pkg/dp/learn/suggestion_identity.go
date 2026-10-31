// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/evidence"
)

// ContentID returns SHA-256 over the versioned canonical JSON representation.
// Ordered slices are intentionally significant; generators must emit stable order.
// nil and empty non-rule metadata slices normalize identically. This validates
// structural safety only; it does not claim representability or certification.
func (c SuggestionContent) ContentID() (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	if c.Limits == nil {
		c.Limits = []string{}
	}
	if c.Withheld == nil {
		c.Withheld = []evidence.WithheldReason{}
	}
	b, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("encode suggestion content: %w", err)
	}
	hash := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(hash[:]), nil
}

// Validate enforces proposal invariants without running the generator.
// Withheld proposals may be inspected as drafts but can never be certified.
func (c SuggestionContent) Validate() error {
	v := c.Versions
	if v.Schema != SuggestionSchemaVersion || v.Observation != evidence.SchemaVersion ||
		v.Generator == "" || v.Evaluator == "" || v.Decoder == "" || v.Profile == "" || v.Snapshot == "" {
		return fmt.Errorf("missing or unsupported suggestion versions")
	}
	if !validDigest(c.EvidenceDigest) {
		return fmt.Errorf("evidenceDigest must be a sha256 digest")
	}
	if len(c.Rules) == 0 {
		return fmt.Errorf("suggestion must contain a rule or atomic bundle")
	}
	ids := make(map[string]bool, len(c.Rules))
	for _, r := range c.Rules {
		if r.ID == "" || ids[r.ID] {
			return fmt.Errorf("rule IDs must be nonempty and unique")
		}
		ids[r.ID] = true
		if r.Action != config.ActionAllow || r.ICS.Mode != "monitor" {
			return fmt.Errorf("suggested rules must be explicit monitor ALLOWs")
		}
		switch r.ICS.Protocol {
		case "modbus", "dnp3", "iec104":
		default:
			return fmt.Errorf("protocol %q has no actionable generator", r.ICS.Protocol)
		}
	}
	return nil
}

func validDigest(s string) bool {
	if len(s) != len("sha256:")+sha256.Size*2 || s[:7] != "sha256:" {
		return false
	}
	b, err := hex.DecodeString(s[7:])
	return err == nil && hex.EncodeToString(b) == s[7:]
}

// ValidateBinding rejects stale/failed/empty replay, not just a successful label.
// Parent coverage and evaluator correctness remain the certifier's responsibility.
func (p Certification) ValidateBinding(c SuggestionContent) error {
	id, err := c.ContentID()
	if err != nil {
		return err
	}
	if p.ContentID != id || p.EvidenceDigest != c.EvidenceDigest || p.Versions != c.Versions {
		return ErrStale
	}
	if len(c.Withheld) != 0 || p.CertifiedAt.IsZero() || len(p.ParentRefs) == 0 || len(p.Counterexamples) != 0 ||
		!successfulReplay(p.Positive) || !successfulReplay(p.Negative) {
		return ErrNotCertified
	}
	return nil
}

func successfulReplay(t ReplayTotals) bool {
	return t.Total > 0 && t.Passed == t.Total && t.Failed == 0
}
