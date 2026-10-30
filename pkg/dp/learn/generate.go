// SPDX-License-Identifier: Apache-2.0
package learn

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strconv"

	"github.com/tonylturner/containd/pkg/cp/config"
	"github.com/tonylturner/containd/pkg/dp/ics/iec104"
	"github.com/tonylturner/containd/pkg/dp/rules"
	"github.com/tonylturner/containd/pkg/evidence"
)

const GeneratorVersion = "exact-1"
const EvaluatorVersion = rules.EvaluatorVersion

// CompatibleVersions deliberately does not reinterpret historical decoder or
// profile inputs. Their immutable fingerprints stay part of content identity.
func CompatibleVersions(v Versions) bool {
	return v.Schema == SuggestionSchemaVersion && v.Observation == evidence.SchemaVersion && v.Generator == GeneratorVersion && v.Evaluator == EvaluatorVersion
}

type Generator struct {
	Store         SuggestionStore
	Certifier     Certifier
	CountWithheld func(context.Context, string, string, evidence.WithheldReason) error
}

type relationGroup struct {
	rules   []config.Rule
	parents []evidence.Observation
}

func (g *Generator) Generate(ctx context.Context, req GenerateRequest) (GenerateResult, error) {
	result := GenerateResult{Suggestions: []Selection{}, Withheld: map[evidence.WithheldReason]uint64{}}
	ds, err := g.Store.GetDataset(ctx, req.DatasetID)
	if err != nil {
		return result, err
	}
	if ds.State != evidence.DatasetSealed || len(ds.Gaps) > 0 {
		return result, ErrNotCertified
	}
	groups := map[string]*relationGroup{}
	withheld := func(o evidence.Observation, reasons []evidence.WithheldReason) error {
		seen := map[evidence.WithheldReason]bool{}
		for _, r := range reasons {
			if seen[r] {
				continue
			}
			seen[r] = true
			result.Withheld[r]++
			if g.CountWithheld != nil {
				if err := g.CountWithheld(ctx, o.ID, GeneratorVersion, r); err != nil {
					return err
				}
			}
		}
		return nil
	}
	cursor := ""
	for {
		page, err := g.Store.ListObservations(ctx, ds.ID, evidence.PageRequest{Limit: 200, Cursor: cursor})
		if err != nil {
			return result, err
		}
		for _, o := range page.Items {
			bundle, reasons := GenerateRelation(o)
			if len(reasons) > 0 {
				if err := withheld(o, reasons); err != nil {
					return result, err
				}
				continue
			}
			key, err := evidence.Digest(bundle)
			if err != nil {
				return result, err
			}
			group := groups[key]
			if group == nil {
				group = &relationGroup{rules: bundle}
				groups[key] = group
			}
			group.parents = append(group.parents, o)
		}
		cursor = page.NextCursor
		if cursor == "" {
			break
		}
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		group := groups[key]
		reasons := closedDomains(group.parents)
		if len(group.parents) > 10000 {
			reasons = append(reasons, evidence.WithheldBudget)
		}
		if len(reasons) > 0 {
			for _, o := range group.parents {
				if err := withheld(o, reasons); err != nil {
					return result, err
				}
			}
			continue
		}
		digest, err := evidence.EvidenceDigest(group.parents)
		if err != nil {
			return result, err
		}
		content := SuggestionContent{Versions: Versions{Schema: SuggestionSchemaVersion, Observation: evidence.SchemaVersion, Generator: GeneratorVersion, Evaluator: EvaluatorVersion, Decoder: ds.DecoderVersion, Profile: ds.ProfileFingerprint, Snapshot: ds.SnapshotFingerprint}, EvidenceDigest: digest, Rules: group.rules, Limits: []string{"Finite boundary replay; selector relations, not transaction or delivery guarantees."}, RequiresCoordinateReview: needsCoordinateReview(group.parents)}
		draft, err := g.Store.PutDraft(ctx, Suggestion{DatasetID: ds.ID, Content: content})
		if err != nil {
			return result, err
		}
		if draft.Status == SuggestionDraft && draft.DatasetID != ds.ID {
			// Content identity excludes source IDs. A failed historical draft
			// cannot acquire different positive references under the same ID.
			for _, o := range group.parents {
				if err := withheld(o, []evidence.WithheldReason{evidence.WithheldReplay}); err != nil {
					return result, err
				}
			}
			continue
		}
		if draft.Status == SuggestionDraft {
			refs := make([]evidence.EvidenceRef, 0, len(group.parents))
			for _, o := range group.parents {
				refs = append(refs, evidence.EvidenceRef{DatasetID: ds.ID, ObservationID: o.ID})
			}
			// Failed replay deliberately returns a concrete, non-pointer proof
			// value for bounded counterexample retention; it is never certified.
			// nosemgrep: trailofbits.go.invalid-usage-of-modified-variable.invalid-usage-of-modified-variable
			proof, err := g.Certifier.Certify(ctx, content, refs)
			if err != nil {
				if len(proof.Counterexamples) > 0 {
					if _, saveErr := g.Store.SaveReplayFailure(ctx, Selection{ID: draft.ID, Revision: draft.Revision}, proof); saveErr != nil {
						return result, saveErr
					}
				}
				for _, o := range group.parents {
					if err := withheld(o, []evidence.WithheldReason{evidence.WithheldReplay}); err != nil {
						return result, err
					}
				}
				continue
			}
			draft, err = g.Store.SaveCertification(ctx, Selection{ID: draft.ID, Revision: draft.Revision}, proof)
			if err != nil {
				return result, err
			}
		}
		if draft.Status == SuggestionCertified || draft.Status == SuggestionReviewed || draft.Status == SuggestionStaged {
			result.Suggestions = append(result.Suggestions, Selection{ID: draft.ID, Revision: draft.Revision})
		}
	}
	return result, nil
}

// GenerateRelation emits the narrow selector relation for a complete parent.
// It never unions targets from different parents or invents missing selectors.
func GenerateRelation(o evidence.Observation) ([]config.Rule, []evidence.WithheldReason) {
	var reasons []evidence.WithheldReason
	if !parentComplete(o) || len(o.Quality.Loss) > 0 {
		reasons = append(reasons, evidence.WithheldIncomplete)
	}
	if !o.Quality.Decoded || len(o.Quality.Undecoded) > 0 {
		reasons = append(reasons, evidence.WithheldUndecoded)
	}
	if len(o.Quality.Conformance) > 0 {
		reasons = append(reasons, evidence.WithheldMalformed)
	}
	if !o.Authority.RoleCertain {
		reasons = append(reasons, evidence.WithheldMissingAuthority)
	}
	if !o.Authority.StandardPort {
		reasons = append(reasons, evidence.WithheldNonstandardPort)
	}
	s := o.Service
	client, e1 := netip.ParseAddr(s.ClientIP)
	server, e2 := netip.ParseAddr(s.ServerIP)
	if e1 != nil || e2 != nil || client.Zone() != "" || server.Zone() != "" || client.Is4() != server.Is4() {
		return nil, append(reasons, evidence.WithheldCoordinates)
	}
	if s.Transport != "tcp" && s.Transport != "udp" || s.ServerPort == 0 || s.Direction != "request" {
		reasons = append(reasons, evidence.WithheldUnsupported)
	}
	base := config.Rule{Sources: []string{netip.PrefixFrom(client.Unmap(), client.Unmap().BitLen()).String()}, Destinations: []string{netip.PrefixFrom(server.Unmap(), server.Unmap().BitLen()).String()}, Protocols: []config.Protocol{{Name: s.Transport, Port: strconv.Itoa(int(s.ServerPort))}}, Action: config.ActionAllow, ICS: config.ICSPredicate{Protocol: s.Protocol, Mode: "monitor", Direction: s.Direction}}
	var bundle []config.Rule
	switch s.Protocol {
	case "modbus":
		m := o.Modbus
		if m == nil || m.UnitID == nil || m.FunctionCode == nil {
			return nil, append(reasons, evidence.WithheldMissingSelector)
		}
		fc := *m.FunctionCode
		if fc == 23 {
			reasons = append(reasons, evidence.WithheldModbusFC23)
		}
		if fc == 8 || fc == 43 {
			reasons = append(reasons, evidence.WithheldModbusSubtype)
		}
		switch fc {
		case 1, 2, 3, 4, 5, 6, 15, 16, 22:
			if len(m.Spans) != 1 {
				reasons = append(reasons, evidence.WithheldMissingSelector)
			}
		case 7, 11, 12, 17:
			if len(m.Spans) != 0 {
				reasons = append(reasons, evidence.WithheldUnsupported)
			}
		default:
			reasons = append(reasons, evidence.WithheldUnsupported)
		}
		base.ICS.UnitID = m.UnitID
		base.ICS.FunctionCode = []uint8{fc}
		base.ICS.Addresses = addressSpecs(m.Spans)
		bundle = append(bundle, base)
	case "dnp3":
		d := o.DNP3
		if d == nil || d.Master == nil || d.Outstation == nil || d.FunctionCode == nil || len(d.Objects) == 0 {
			return nil, append(reasons, evidence.WithheldMissingSelector)
		}
		base.ICS.Masters = []uint16{*d.Master}
		base.ICS.Outstations = []uint16{*d.Outstation}
		base.ICS.FunctionCode = []uint8{*d.FunctionCode}
		for _, obj := range d.Objects {
			reasons = append(reasons, dnpRequirements(obj)...)
			if obj.Group == nil || obj.Variation == nil {
				reasons = append(reasons, evidence.WithheldMissingSelector)
				continue
			}
			r := base
			r.ICS.Groups = []int{int(*obj.Group)}
			r.ICS.Variations = []int{int(*obj.Variation)}
			r.ICS.Addresses = addressSpecs(obj.Spans)
			bundle = append(bundle, r)
		}
	case "iec104":
		d := o.IEC104
		if d == nil || d.TypeID == nil || d.CA == nil || d.COT == nil || d.Originator == nil || d.Negative == nil || d.Test == nil {
			return nil, append(reasons, evidence.WithheldMissingSelector)
		}
		if !client.Is4() || s.Transport != "tcp" {
			reasons = append(reasons, evidence.WithheldCoordinates)
		}
		if d.APCIType != "I" || iec104.ClassOf(*d.TypeID) != "control" {
			reasons = append(reasons, evidence.WithheldIECNonCommand)
		}
		if *d.CA == 65535 {
			reasons = append(reasons, evidence.WithheldIECBroadcast)
		}
		if len(d.Objects) == 0 || uint32(len(d.Objects)) != o.ObjectCount {
			reasons = append(reasons, evidence.WithheldIncomplete)
		}
		base.ICS.TypeIDs = []int{int(*d.TypeID)}
		base.ICS.CA = []uint16{*d.CA}
		base.ICS.COT = []int{int(*d.COT)}
		base.ICS.Originators = []int{int(*d.Originator)}
		base.ICS.Negative = d.Negative
		base.ICS.Test = d.Test
		for i, obj := range d.Objects {
			if obj.IOA == nil || obj.Select == nil || obj.Index != uint32(i) {
				reasons = append(reasons, evidence.WithheldMissingSelector)
				continue
			}
			r := base
			r.ICS.IOA = []config.IOARange{{Start: *obj.IOA, End: *obj.IOA}}
			r.ICS.SelectExecute = "execute"
			if *obj.Select {
				r.ICS.SelectExecute = "select"
				reasons = append(reasons, evidence.WithheldIECSBO)
			}
			bundle = append(bundle, r)
		}
	case "cip":
		reasons = append(reasons, evidence.WithheldCIP)
	default:
		reasons = append(reasons, evidence.WithheldUnsupported)
	}
	if len(bundle) > 128 {
		reasons = append(reasons, evidence.WithheldBudget)
	}
	if len(reasons) > 0 {
		return nil, reasons
	}
	unique := map[string]config.Rule{}
	for _, r := range bundle {
		id, _ := evidence.Digest(r)
		r.ID = "exact-" + id[7:]
		unique[r.ID] = r
	}
	bundle = nil
	for _, r := range unique {
		bundle = append(bundle, r)
	}
	sort.Slice(bundle, func(i, j int) bool { return bundle[i].ID < bundle[j].ID })
	return bundle, nil
}

func addressSpecs(spans []evidence.Span) []string {
	var out []string
	for _, sp := range spans {
		out = append(out, fmt.Sprintf("%d-%d", sp.First, sp.Last))
	}
	sort.Strings(out)
	return out
}

type objectRequirement struct {
	reason evidence.WithheldReason
	fails  func(evidence.DNP3Object) bool
}

var dnpTable = []objectRequirement{
	{evidence.WithheldDNP3AllObjects, func(o evidence.DNP3Object) bool { return o.AllObjects }},
	{evidence.WithheldDNP3Variation, func(o evidence.DNP3Object) bool { return o.Variation == nil || *o.Variation == 0 }},
	{evidence.WithheldDNP3CountOnly, func(o evidence.DNP3Object) bool { return o.Count == nil || len(o.Spans) == 0 }},
	{evidence.WithheldDNP3Indexless, func(o evidence.DNP3Object) bool {
		return o.Qualifier == nil || (*o.Qualifier > 2 && *o.Qualifier != 0x17 && *o.Qualifier != 0x28 && *o.Qualifier != 0x39)
	}},
}

func dnpRequirements(o evidence.DNP3Object) []evidence.WithheldReason {
	var reasons []evidence.WithheldReason
	for _, r := range dnpTable {
		if r.fails(o) {
			reasons = append(reasons, r.reason)
		}
	}
	return reasons
}

type closedRequirement struct {
	reason evidence.WithheldReason
	domain func(uint8) []string
	value  func(evidence.IEC104Object) string
}

func numberDigests(values ...uint8) []string {
	var out []string
	for _, v := range values {
		d, _ := evidence.Digest(v)
		out = append(out, d)
	}
	return out
}

var iecTable = []closedRequirement{
	{evidence.WithheldIECValue, func(t uint8) []string {
		switch t {
		case 45, 58:
			return numberDigests(0, 1)
		case 46, 47, 59, 60:
			return numberDigests(1, 2)
		default:
			return nil
		}
	}, func(o evidence.IEC104Object) string { return o.ValueDigest }},
	{evidence.WithheldIECQualifier, func(t uint8) []string {
		var out []string
		size := 32
		if t == 48 || t == 49 || t == 50 || t == 61 || t == 62 || t == 63 {
			size = 128
		}
		for i := range size {
			out = append(out, strconv.Itoa(i))
		}
		return out
	}, func(o evidence.IEC104Object) string {
		if o.Qualifier == nil {
			return ""
		}
		return strconv.Itoa(int(*o.Qualifier))
	}},
}

func closedDomains(parents []evidence.Observation) []evidence.WithheldReason {
	if len(parents) == 0 {
		return nil
	}
	if parents[0].Modbus != nil {
		return modbusDomains(parents)
	}
	if parents[0].DNP3 != nil {
		return dnpDomains(parents)
	}
	if parents[0].IEC104 == nil {
		return nil
	}
	var reasons []evidence.WithheldReason
	for _, r := range iecTable {
		domain := r.domain(*parents[0].IEC104.TypeID)
		sets := map[uint32]map[string]bool{}
		for _, p := range parents {
			for _, o := range p.IEC104.Objects {
				if o.IOA == nil {
					continue
				}
				if sets[*o.IOA] == nil {
					sets[*o.IOA] = map[string]bool{}
				}
				sets[*o.IOA][r.value(o)] = true
			}
		}
		complete := len(domain) > 0 && len(sets) > 0
		for _, set := range sets {
			for _, value := range domain {
				complete = complete && set[value]
			}
			complete = complete && len(set) == len(domain)
		}
		if !complete {
			reasons = append(reasons, r.reason)
		}
	}
	// Full marginal domains are insufficient if value and qualifier remain
	// correlated. The unqualified predicate admits their Cartesian product.
	if len(reasons) == 0 && len(iecTable) > 1 {
		products := map[uint32]map[string]bool{}
		for _, p := range parents {
			for _, obj := range p.IEC104.Objects {
				if obj.IOA == nil {
					continue
				}
				if products[*obj.IOA] == nil {
					products[*obj.IOA] = map[string]bool{}
				}
				var tuple []string
				for _, r := range iecTable {
					tuple = append(tuple, r.value(obj))
				}
				digest, _ := evidence.Digest(tuple)
				products[*obj.IOA][digest] = true
			}
		}
		expected := 1
		for _, r := range iecTable {
			expected *= len(r.domain(*parents[0].IEC104.TypeID))
		}
		for _, product := range products {
			if len(product) != expected {
				reasons = append(reasons, evidence.WithheldCorrelation)
				break
			}
		}
	}
	return reasons
}

func modbusDomains(parents []evidence.Observation) []evidence.WithheldReason {
	m := parents[0].Modbus
	if m.FunctionCode == nil {
		return []evidence.WithheldReason{evidence.WithheldMissingSelector}
	}
	fc := *m.FunctionCode
	if fc != 5 && fc != 6 && fc != 15 && fc != 16 && fc != 22 && fc != 23 {
		return nil
	}
	domain := 0
	if fc == 5 {
		domain = 2
	}
	if fc == 15 && len(m.Spans) == 1 {
		n := uint64(m.Spans[0].Last) - uint64(m.Spans[0].First) + 1
		if n <= 14 {
			domain = 1 << n
		}
	}
	seen := map[string]bool{}
	for _, p := range parents {
		v := p.Modbus.Values
		if fc == 5 && len(v) == 1 && (v[0] == 0 || v[0] == 0xff00) {
			d, _ := evidence.Digest(v)
			seen[d] = true
		}
		if fc == 15 && domain > 0 && len(v) == int(m.Spans[0].Last-m.Spans[0].First+1) {
			valid := true
			for _, value := range v {
				valid = valid && value <= 1
			}
			if valid {
				d, _ := evidence.Digest(v)
				seen[d] = true
			}
		}
	}
	if domain > 0 && len(seen) == domain {
		return nil
	}
	return []evidence.WithheldReason{evidence.WithheldModbusValues}
}

func needsCoordinateReview(parents []evidence.Observation) bool {
	for _, p := range parents {
		if p.Service.Coordinates == evidence.CoordinatesWire {
			return true
		}
	}
	return false
}

type dnpClosedRequirement struct {
	reason evidence.WithheldReason
	domain func(evidence.DNP3Object) map[string]bool
	value  func(evidence.DNP3Object) string
}

var dnpClosedTable = []dnpClosedRequirement{{evidence.WithheldDNP3Values, dnpValueDomain, func(o evidence.DNP3Object) string { return o.DataDigest }}}

func dnpDomains(parents []evidence.Observation) []evidence.WithheldReason {
	var reasons []evidence.WithheldReason
	for _, requirement := range dnpClosedTable {
		complete := true
		for _, obj := range parents[0].DNP3.Objects {
			if requirement.value(obj) == "" {
				continue
			}
			domain := requirement.domain(obj)
			seen := map[string]bool{}
			key := dnpTargetKey(obj)
			for _, p := range parents {
				found := false
				for _, candidate := range p.DNP3.Objects {
					if dnpTargetKey(candidate) != key {
						continue
					}
					value := requirement.value(candidate)
					if !domain[value] {
						complete = false
					}
					seen[value] = true
					found = true
				}
				complete = complete && found
			}
			complete = complete && len(domain) > 0 && len(seen) == len(domain)
		}
		if !complete {
			reasons = append(reasons, requirement.reason)
		}
	}
	return reasons
}
func dnpValueDomain(o evidence.DNP3Object) map[string]bool {
	if o.Group == nil || o.Variation == nil || o.Count == nil {
		return nil
	}
	bits := map[uint16]uint32{0x0101: 1, 0x0301: 2, 0x0a01: 1, 0x5001: 1}[uint16(*o.Group)<<8|uint16(*o.Variation)]
	if bits == 0 || *o.Count == 0 || uint64(bits)*uint64(*o.Count) > 14 {
		return nil
	}
	domain := map[string]bool{}
	for state := range 1 << (bits * *o.Count) {
		values := make([]int, int(*o.Count))
		for i := range values {
			values[i] = (state >> (uint32(i) * bits)) & ((1 << bits) - 1)
		}
		digest, _ := evidence.Digest(values)
		domain[digest] = true
	}
	return domain
}

func parentComplete(o evidence.Observation) bool {
	if !o.Quality.Complete {
		return false
	}
	if o.IEC104 != nil {
		if len(o.IEC104.Objects) != int(o.ObjectCount) {
			return false
		}
		for i, obj := range o.IEC104.Objects {
			if obj.Index != uint32(i) {
				return false
			}
		}
	}
	if o.DNP3 != nil {
		for i, obj := range o.DNP3.Objects {
			if obj.Index != uint32(i) {
				return false
			}
			if obj.Count != nil && len(obj.Spans) > 0 {
				var n uint64
				for _, sp := range obj.Spans {
					if sp.Last < sp.First {
						return false
					}
					n += uint64(sp.Last) - uint64(sp.First) + 1
				}
				if n != uint64(*obj.Count) {
					return false
				}
			}
		}
	}
	return true
}

func dnpTargetKey(o evidence.DNP3Object) string {
	key, _ := evidence.Digest(struct {
		Group, Variation *uint8
		Spans            []evidence.Span
	}{o.Group, o.Variation, o.Spans})
	return key
}
