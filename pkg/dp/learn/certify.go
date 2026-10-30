// SPDX-License-Identifier: Apache-2.0
package learn

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"github.com/tonylturner/containd/pkg/cp/compile"
	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/ics/project"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/evidence"
)

// CompilerCertifier has no network replay or active engine dependency.
type CompilerCertifier struct {
	Store evidence.Store
	Now   func() time.Time
}

func (c *CompilerCertifier) Certify(ctx context.Context, content SuggestionContent, refs []evidence.EvidenceRef) (Certification, error) {
	proof := Certification{EvidenceDigest: content.EvidenceDigest, Versions: content.Versions, ParentRefs: refs, Counterexamples: []Counterexample{}}
	id, err := content.ContentID()
	if err != nil {
		return proof, err
	}
	proof.ContentID = id
	if len(refs) == 0 || len(refs) > 10000 || len(content.Rules) > 128 || len(content.Withheld) > 0 || !CompatibleVersions(content.Versions) {
		return proof, ErrNotCertified
	}
	parents, err := loadParents(ctx, c.Store, refs)
	if err != nil {
		return proof, err
	}
	digest, err := evidence.EvidenceDigest(parents)
	if err != nil {
		return proof, err
	}
	if digest != content.EvidenceDigest {
		return proof, ErrStale
	}
	cfg := config.DefaultConfig()
	cfg.Firewall.Rules = content.Rules
	cfg.Firewall.DefaultAction = config.ActionDeny
	cfg.Firewall.NAT.Enabled = false
	snapshot, err := compile.CompileSnapshot(cfg)
	if err != nil {
		return proof, err
	}
	evaluator := rules.NewEvaluator(&snapshot)
	accepts := func(o evidence.Observation) bool {
		contexts, err := project.Observation(o)
		if err != nil || len(contexts) == 0 {
			return false
		}
		for _, context := range contexts {
			if evaluator.AnyMatch(context) == nil {
				return false
			}
		}
		return true
	}
	failure := func(ref evidence.EvidenceRef, mutation string, o evidence.Observation, expected, actual string) {
		if len(proof.Counterexamples) >= 50 {
			return
		}
		digest, _ := evidence.Digest(o)
		proof.Counterexamples = append(proof.Counterexamples, Counterexample{Parent: ref, Mutation: mutation, Expected: expected, Actual: actual, ContextDigest: digest})
	}
	for i, o := range parents {
		if err := ctx.Err(); err != nil {
			return proof, err
		}
		if o.DecoderVersion != content.Versions.Decoder || o.ProfileFingerprint != content.Versions.Profile || o.SnapshotFingerprint != content.Versions.Snapshot {
			return proof, ErrStale
		}
		proof.Positive.Total++
		if accepts(o) {
			proof.Positive.Passed++
		} else {
			proof.Positive.Failed++
			failure(refs[i], "positive", o, "accept", "reject")
		}
		for _, mutation := range boundaryMutations(o) {
			if proof.Negative.Total >= 100000 {
				return proof, fmt.Errorf("negative replay budget exceeded")
			}
			proof.Negative.Total++
			if !accepts(mutation.parent) {
				proof.Negative.Passed++
			} else {
				proof.Negative.Failed++
				failure(refs[i], mutation.name, mutation.parent, "reject", "accept")
			}
		}
	}
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	proof.CertifiedAt = now().UTC()
	if err := proof.ValidateBinding(content); err != nil {
		return proof, err
	}
	return proof, nil
}

func loadParents(ctx context.Context, store evidence.Store, refs []evidence.EvidenceRef) ([]evidence.Observation, error) {
	byDataset := map[string]map[string]evidence.Observation{}
	seen := map[string]bool{}
	for _, ref := range refs {
		key := ref.DatasetID + "/" + ref.ObservationID
		if ref.DatasetID == "" || ref.ObservationID == "" || seen[key] {
			return nil, ErrNotCertified
		}
		seen[key] = true
		if byDataset[ref.DatasetID] != nil {
			continue
		}
		ds, err := store.GetDataset(ctx, ref.DatasetID)
		if err != nil {
			return nil, err
		}
		if ds.State != evidence.DatasetSealed || len(ds.Gaps) > 0 {
			return nil, ErrNotCertified
		}
		found := map[string]evidence.Observation{}
		cursor := ""
		for {
			page, err := store.ListObservations(ctx, ds.ID, evidence.PageRequest{Limit: 200, Cursor: cursor})
			if err != nil {
				return nil, err
			}
			for _, o := range page.Items {
				found[o.ID] = o
			}
			cursor = page.NextCursor
			if cursor == "" {
				break
			}
		}
		byDataset[ds.ID] = found
	}
	out := make([]evidence.Observation, 0, len(refs))
	for _, ref := range refs {
		o, ok := byDataset[ref.DatasetID][ref.ObservationID]
		if !ok {
			return nil, ErrExpired
		}
		out = append(out, o)
	}
	return out, nil
}

type mutation struct {
	name   string
	parent evidence.Observation
}

func boundaryMutations(o evidence.Observation) []mutation {
	var out []mutation
	add := func(name string, edit func(*evidence.Observation)) {
		b, _ := json.Marshal(o)
		var copy evidence.Observation
		_ = json.Unmarshal(b, &copy)
		edit(&copy)
		out = append(out, mutation{name, copy})
	}
	add("client", func(p *evidence.Observation) { p.Service.ClientIP = differentIP(p.Service.ClientIP) })
	add("server", func(p *evidence.Observation) { p.Service.ServerIP = differentIP(p.Service.ServerIP) })
	add("service", func(p *evidence.Observation) { p.Service.ServerPort++ })
	add("transport", func(p *evidence.Observation) {
		if p.Service.Transport == "tcp" {
			p.Service.Transport = "udp"
		} else {
			p.Service.Transport = "tcp"
		}
	})
	add("direction", func(p *evidence.Observation) { p.Service.Direction = "response" })
	switch {
	case o.Modbus != nil:
		add("unit", func(p *evidence.Observation) { *p.Modbus.UnitID++ })
		add("missing_unit", func(p *evidence.Observation) { p.Modbus.UnitID = nil })
		add("function", func(p *evidence.Observation) { *p.Modbus.FunctionCode++ })
		add("missing_function", func(p *evidence.Observation) { p.Modbus.FunctionCode = nil })
		if len(o.Modbus.Spans) > 0 {
			sp := o.Modbus.Spans[0]
			if sp.First > 0 {
				add("span_before", func(p *evidence.Observation) {
					p.Modbus.Spans[0] = evidence.Span{First: sp.First - 1, Last: sp.First - 1, Role: sp.Role}
				})
			}
			if sp.Last < 65535 {
				add("span_after", func(p *evidence.Observation) {
					p.Modbus.Spans[0] = evidence.Span{First: sp.Last + 1, Last: sp.Last + 1, Role: sp.Role}
				})
			}
			add("missing_span", func(p *evidence.Observation) { p.Modbus.Spans = nil })
		}
	case o.DNP3 != nil:
		add("master", func(p *evidence.Observation) { *p.DNP3.Master++ })
		add("outstation", func(p *evidence.Observation) { *p.DNP3.Outstation++ })
		add("function", func(p *evidence.Observation) { *p.DNP3.FunctionCode++ })
		groups := map[uint8]bool{}
		for _, obj := range o.DNP3.Objects {
			if obj.Group != nil {
				groups[*obj.Group] = true
			}
		}
		different, exists := unusedByte(groups)
		if exists {
			add("extra_header", func(p *evidence.Observation) {
				obj := p.DNP3.Objects[0]
				obj.Group = &different
				p.DNP3.Objects = append(p.DNP3.Objects, obj)
				p.ObjectCount++
			})
		}
		for i := range o.DNP3.Objects {
			add(fmt.Sprintf("missing_group_%d", i), func(p *evidence.Observation) { p.DNP3.Objects[i].Group = nil })
			add(fmt.Sprintf("missing_variation_%d", i), func(p *evidence.Observation) { p.DNP3.Objects[i].Variation = nil })
			add(fmt.Sprintf("missing_indexes_%d", i), func(p *evidence.Observation) { p.DNP3.Objects[i].Spans = nil })
			for _, value := range []uint32{0, ^uint32(0)} {
				obj := o.DNP3.Objects[i]
				if dnpRelationContains(o.DNP3, obj, value) {
					continue
				}
				add(fmt.Sprintf("index_%d_%d", i, value), func(p *evidence.Observation) {
					p.DNP3.Objects[i].Spans = []evidence.Span{{First: value, Last: value, Role: "target"}}
				})
			}
			for j := range o.DNP3.Objects {
				if i == j {
					continue
				}
				obj := o.DNP3.Objects[i]
				other := o.DNP3.Objects[j]
				if len(obj.Spans) == 0 || other.Group == nil || other.Variation == nil {
					continue
				}
				obj.Group = other.Group
				obj.Variation = other.Variation
				if dnpRelationContains(o.DNP3, obj, obj.Spans[0].First) {
					continue
				}
				add(fmt.Sprintf("recombined_header_%d_%d", i, j), func(p *evidence.Observation) {
					p.DNP3.Objects[i].Group = other.Group
					p.DNP3.Objects[i].Variation = other.Variation
				})
			}
		}
	case o.IEC104 != nil:
		add("type", func(p *evidence.Observation) { *p.IEC104.TypeID++ })
		add("ca", func(p *evidence.Observation) { *p.IEC104.CA++ })
		add("cot", func(p *evidence.Observation) { *p.IEC104.COT++ })
		add("originator", func(p *evidence.Observation) { *p.IEC104.Originator++ })
		add("negative", func(p *evidence.Observation) { *p.IEC104.Negative = !*p.IEC104.Negative })
		add("test", func(p *evidence.Observation) { *p.IEC104.Test = !*p.IEC104.Test })
		used := map[uint32]bool{}
		for _, obj := range o.IEC104.Objects {
			if obj.IOA != nil {
				used[*obj.IOA] = true
			}
		}
		outside := uint32(0)
		for used[outside] {
			outside++
		}
		add("extra_object", func(p *evidence.Observation) {
			obj := p.IEC104.Objects[0]
			obj.IOA = &outside
			p.IEC104.Objects = append(p.IEC104.Objects, obj)
			p.ObjectCount++
		})
		for i := range o.IEC104.Objects {
			add(fmt.Sprintf("missing_ioa_%d", i), func(p *evidence.Observation) { p.IEC104.Objects[i].IOA = nil })
			add(fmt.Sprintf("select_execute_%d", i), func(p *evidence.Observation) { *p.IEC104.Objects[i].Select = !*p.IEC104.Objects[i].Select })
		}
	}
	return out
}
func differentIP(text string) string {
	ip, err := netip.ParseAddr(text)
	if err != nil {
		return ""
	}
	b := ip.As16()
	b[15] ^= 1
	result := netip.AddrFrom16(b)
	if ip.Is4() {
		result = result.Unmap()
	}
	return result.String()
}
func unusedByte(used map[uint8]bool) (uint8, bool) {
	for i := range 256 {
		if !used[uint8(i)] {
			return uint8(i), true
		}
	}
	return 0, false
}
func dnpRelationContains(d *evidence.DNP3, obj evidence.DNP3Object, index uint32) bool {
	for _, allowed := range d.Objects {
		if allowed.Group == nil || allowed.Variation == nil || obj.Group == nil || obj.Variation == nil || *allowed.Group != *obj.Group || *allowed.Variation != *obj.Variation {
			continue
		}
		for _, sp := range allowed.Spans {
			if index >= sp.First && index <= sp.Last {
				return true
			}
		}
	}
	return false
}
