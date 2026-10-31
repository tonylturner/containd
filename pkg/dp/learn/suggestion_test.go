// SPDX-License-Identifier: Apache-2.0

package learn

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/evidence"
)

func proposalContent() SuggestionContent {
	unit := uint8(0)
	return SuggestionContent{
		Versions:       Versions{Schema: SuggestionSchemaVersion, Observation: evidence.SchemaVersion, Generator: "modbus-1", Evaluator: "dp-1", Decoder: "decode-1", Profile: "profile-1", Snapshot: "snapshot-1"},
		EvidenceDigest: "sha256:" + strings.Repeat("a", 64),
		Rules:          []config.Rule{{ID: "observed-relation-1", Action: config.ActionAllow, Sources: []string{"192.0.2.1/32"}, Destinations: []string{"192.0.2.2/32"}, Protocols: []config.Protocol{{Name: "tcp", Port: "502"}}, ICS: config.ICSPredicate{Protocol: "modbus", Mode: "monitor", UnitID: &unit, FunctionCode: []uint8{3}, Direction: "request", Addresses: []string{"0-1"}}}},
	}
}

func proofFor(t *testing.T, c SuggestionContent) Certification {
	t.Helper()
	id, err := c.ContentID()
	if err != nil {
		t.Fatal(err)
	}
	return Certification{ContentID: id, EvidenceDigest: c.EvidenceDigest, Versions: c.Versions, CertifiedAt: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC), ParentRefs: []evidence.EvidenceRef{{DatasetID: "d1", ObservationID: "p1"}}, Positive: ReplayTotals{Total: 1, Passed: 1}, Negative: ReplayTotals{Total: 10, Passed: 10}}
}

func TestSuggestionContentIdentity(t *testing.T) {
	c := proposalContent()
	id, err := c.ContentID()
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip SuggestionContent
	if err := json.Unmarshal(data, &roundTrip); err != nil {
		t.Fatal(err)
	}
	got, err := roundTrip.ContentID()
	if err != nil || got != id {
		t.Fatalf("unstable identity: %s, %v", got, err)
	}
	roundTrip.Limits = []string{}
	roundTrip.Withheld = []evidence.WithheldReason{}
	got, err = roundTrip.ContentID()
	if err != nil || got != id {
		t.Fatal("empty/nil metadata changed identity")
	}
	for _, tt := range []struct {
		name   string
		change func(*SuggestionContent)
	}{
		{"rule bytes", func(c *SuggestionContent) { c.Rules[0].ICS.Addresses = []string{"0-2"} }},
		{"service", func(c *SuggestionContent) { c.Rules[0].Protocols[0].Port = "503" }},
		{"evidence", func(c *SuggestionContent) { c.EvidenceDigest = "sha256:" + strings.Repeat("b", 64) }},
		{"generator", func(c *SuggestionContent) { c.Versions.Generator += "-different" }},
		{"evaluator", func(c *SuggestionContent) { c.Versions.Evaluator += "-different" }},
		{"profile", func(c *SuggestionContent) { c.Versions.Profile += "-different" }},
		{"coordinate review", func(c *SuggestionContent) { c.RequiresCoordinateReview = true }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			changed := proposalContent()
			tt.change(&changed)
			other, err := changed.ContentID()
			if err != nil {
				t.Fatal(err)
			}
			if other == id {
				t.Fatal("content changed without identity changing")
			}
		})
	}
}

func TestSuggestionContentInvariants(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change func(*SuggestionContent)
	}{
		{"inherit", func(c *SuggestionContent) { c.Rules[0].ICS.Mode = "" }},
		{"enforce", func(c *SuggestionContent) { c.Rules[0].ICS.Mode = "enforce" }},
		{"deny", func(c *SuggestionContent) { c.Rules[0].Action = config.ActionDeny }},
		{"CIP", func(c *SuggestionContent) { c.Rules[0].ICS.Protocol = "cip" }},
		{"empty", func(c *SuggestionContent) { c.Rules = nil }},
		{"duplicate", func(c *SuggestionContent) { c.Rules = append(c.Rules, c.Rules[0]) }},
		{"schema", func(c *SuggestionContent) { c.Versions.Schema += "-different" }},
		{"observation schema", func(c *SuggestionContent) { c.Versions.Observation += "-different" }},
		{"digest", func(c *SuggestionContent) { c.EvidenceDigest = "not-a-digest" }},
		{"noncanonical digest", func(c *SuggestionContent) { c.EvidenceDigest = "sha256:" + strings.ToUpper(c.EvidenceDigest[7:]) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := proposalContent()
			tt.change(&c)
			if _, err := c.ContentID(); err == nil {
				t.Fatal("accepted unsafe proposal")
			}
		})
	}
}

func TestCertificationBinding(t *testing.T) {
	c := proposalContent()
	p := proofFor(t, c)
	if err := p.ValidateBinding(c); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name   string
		change func(*Certification)
		want   error
	}{
		{"rule identity", func(p *Certification) { p.ContentID += "-different" }, ErrStale},
		{"evidence digest", func(p *Certification) { p.EvidenceDigest += "-different" }, ErrStale},
		{"evaluator", func(p *Certification) { p.Versions.Evaluator += "-different" }, ErrStale},
		{"no positives", func(p *Certification) { p.Positive = ReplayTotals{} }, ErrNotCertified},
		{"no negatives", func(p *Certification) { p.Negative = ReplayTotals{} }, ErrNotCertified},
		{"positive miss", func(p *Certification) { p.Positive.Passed-- }, ErrNotCertified},
		{"negative match", func(p *Certification) { p.Negative.Passed--; p.Negative.Failed++ }, ErrNotCertified},
		{"missing parents", func(p *Certification) { p.ParentRefs = nil }, ErrNotCertified},
		{"counterexample", func(p *Certification) { p.Counterexamples = []Counterexample{{Mutation: "extra_object"}} }, ErrNotCertified},
	} {
		t.Run(tt.name, func(t *testing.T) {
			changed := p
			tt.change(&changed)
			if err := changed.ValidateBinding(c); !errors.Is(err, tt.want) {
				t.Fatalf("got %v; want %v", err, tt.want)
			}
		})
	}
	c.Withheld = []evidence.WithheldReason{evidence.WithheldModbusValues}
	p = proofFor(t, c)
	if err := p.ValidateBinding(c); !errors.Is(err, ErrNotCertified) {
		t.Fatalf("withheld content certified: %v", err)
	}
}

func TestSuggestionJSONRoundTrip(t *testing.T) {
	c := proposalContent()
	p := proofFor(t, c)
	for _, status := range []SuggestionStatus{SuggestionDraft, SuggestionCertified, SuggestionReviewed, SuggestionStaged, SuggestionRejected, SuggestionExpired} {
		t.Run(string(status), func(t *testing.T) {
			s := Suggestion{ID: p.ContentID, Revision: 3, DatasetID: "d1", Content: c, Status: status, CreatedAt: p.CertifiedAt, ExpiresAt: p.CertifiedAt.Add(evidence.Retention), Proof: &p, Review: &Review{Actor: "admin", At: p.CertifiedAt, Revision: 2}, LegacyOverlaps: []LegacyOverlap{{RuleID: "learned-old", Reason: "overlap heuristic only"}}}
			data, err := json.Marshal(s)
			if err != nil {
				t.Fatal(err)
			}
			var got Suggestion
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(s, got) {
				t.Fatalf("suggestion round trip changed: %s", data)
			}
			id, err := got.Content.ContentID()
			if err != nil || id != s.ID {
				t.Fatalf("workflow metadata changed content identity: %v", err)
			}
		})
	}
}
