// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"testing"
	"time"
)

func TestSemanticDigestExcludesLocationNotRelation(t *testing.T) {
	o := observation()
	o.Service.ServerPort = 502
	original, err := o.SemanticDigest()
	if err != nil {
		t.Fatal(err)
	}
	o.ID, o.DatasetID, o.ConnectionID, o.ParentID = "other-id", "other-dataset", "other-incarnation", "other-parent"
	o.Source, o.IngestedAt, o.Evidence = SourceLive, time.Now(), nil
	got, err := o.SemanticDigest()
	if err != nil || got != original {
		t.Fatalf("storage location changed semantic identity: %s %v", got, err)
	}
	for _, change := range []func(*Observation){
		func(p *Observation) { p.Service.ServerPort++ },
		func(p *Observation) { p.Quality.Complete = false },
		func(p *Observation) { p.Modbus = &Modbus{FunctionCode: ptr(uint8(4))} },
		func(p *Observation) { p.CapturedAt = p.CapturedAt.Add(time.Second) },
	} {
		changed := o
		change(&changed)
		digest, err := changed.SemanticDigest()
		if err != nil || digest == original {
			t.Fatalf("semantic change omitted from digest: %v", err)
		}
	}
}

func TestEvidenceDigestDeduplicatesSemanticsNotReferences(t *testing.T) {
	a := observation()
	b := a
	b.ParentID = "second-captured-message"
	c := a
	c.CapturedAt = c.CapturedAt.Add(time.Second)
	one, err := EvidenceDigest([]Observation{a, c})
	if err != nil {
		t.Fatal(err)
	}
	two, err := EvidenceDigest([]Observation{c, b, a})
	if err != nil || one != two {
		t.Fatalf("digest depends on source order or duplicate semantics: %v", err)
	}
}

func TestImportIdentityBindsAllAuthorities(t *testing.T) {
	capture, err := Digest("capture")
	if err != nil {
		t.Fatal(err)
	}
	d := Dataset{CaptureSHA256: capture, DecoderVersion: "decoder", ProfileFingerprint: "profile", SnapshotFingerprint: "snapshot"}
	id, err := ImportID(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Dataset){
		func(p *Dataset) { p.CaptureSHA256, _ = Digest(p.CaptureSHA256 + "-different") },
		func(p *Dataset) { p.DecoderVersion += "-different" },
		func(p *Dataset) { p.ProfileFingerprint += "-different" },
		func(p *Dataset) { p.SnapshotFingerprint += "-different" },
	} {
		changed := d
		change(&changed)
		other, err := ImportID(changed)
		if err != nil || other == id {
			t.Fatalf("capture authority omitted from ID: %v", err)
		}
	}
	d.CaptureSHA256 = "invalid"
	if _, err := ImportID(d); err == nil {
		t.Fatal("accepted a non-digest capture identity")
	}
}
