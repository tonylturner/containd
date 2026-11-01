// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// NormalizationVersion versions the live/PCAP event-to-observation adapter,
// independently of decoder and storage schemas. Bump when retained authority or
// normalized semantics change so an import never reuses obsolete observations.
const NormalizationVersion = "binding-2"

// ImportID binds a capture to the semantic authorities used to decode and
// normalize it. Historical IDs remain readable but are never reused here.
// Reimporting the same capture under the same authorities cannot renew a lease.
func ImportID(d Dataset) (string, error) {
	if len(d.CaptureSHA256) != 71 || d.CaptureSHA256[:7] != "sha256:" {
		return "", fmt.Errorf("captureSha256 must be a lowercase sha256 digest")
	}
	raw, err := hex.DecodeString(d.CaptureSHA256[7:])
	if err != nil || hex.EncodeToString(raw) != d.CaptureSHA256[7:] || d.DecoderVersion == "" || d.ProfileFingerprint == "" || d.SnapshotFingerprint == "" {
		return "", fmt.Errorf("missing or invalid capture identity")
	}
	return Digest([]string{SchemaVersion, d.CaptureSHA256, d.DecoderVersion, d.ProfileFingerprint, d.SnapshotFingerprint, NormalizationVersion})
}

// Digest hashes canonical JSON. Struct field and slice order are significant.
func Digest(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

// SemanticDigest excludes storage identity and source location, not authority or
// quality. Equal messages still retain distinct positive replay references.
func (o Observation) SemanticDigest() (string, error) {
	o.ID, o.DatasetID, o.ConnectionID, o.ParentID, o.ParentDigest = "", "", "", "", ""
	o.Source, o.Evidence = "", nil
	// A zero instant must not depend on the ingestion clock.
	o.IngestedAt = Observation{}.IngestedAt
	o.Outcome.Evidence = nil
	return Digest(o)
}

// EvidenceDigest is source-order independent but retains distinct semantics.
func EvidenceDigest(parents []Observation) (string, error) {
	set := map[string]bool{}
	for _, o := range parents {
		d, err := o.SemanticDigest()
		if err != nil {
			return "", err
		}
		set[d] = true
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return Digest(keys)
}
