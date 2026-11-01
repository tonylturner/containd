// SPDX-License-Identifier: Apache-2.0
package pcap_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
	"github.com/tonylturner/containd/pkg/dp/learn"
	"github.com/tonylturner/containd/pkg/dp/pcap"
	"github.com/tonylturner/containd/pkg/evidence"
	"github.com/tonylturner/containd/pkg/evidence/sqlite"
)

func check(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func meta() evidence.Dataset {
	return evidence.Dataset{Source: evidence.SourcePCAP, CaptureSHA256: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", DecoderVersion: "ics-1", ProfileFingerprint: "profile", SnapshotFingerprint: "snapshot"}
}
func open(t *testing.T) *sqlite.Store {
	t.Helper()
	s, e := sqlite.Open(filepath.Join(t.TempDir(), "evidence.db"), sqlite.Options{CompatibleProof: learn.CompatibleVersions})
	check(t, e)
	t.Cleanup(func() { _ = s.Close() })
	return s
}
func frame(seq uint32, addr byte) []byte {
	b := make([]byte, 66)
	binary.BigEndian.PutUint16(b[12:], 0x800)
	b[14] = 0x45
	binary.BigEndian.PutUint16(b[16:], 52)
	b[23] = 6
	copy(b[26:], []byte{10, 0, 0, addr})
	copy(b[30:], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint16(b[34:], 49152)
	binary.BigEndian.PutUint16(b[36:], 502)
	binary.BigEndian.PutUint32(b[38:], seq)
	b[46] = 5 << 4
	copy(b[54:], []byte{0, 1, 0, 0, 0, 6, 1, 3, 0, 0, 0, 10})
	return b
}
func capture(frames [][]byte, orig []int) []byte {
	b := make([]byte, 24)
	binary.LittleEndian.PutUint32(b, 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(b[4:], 2)
	binary.LittleEndian.PutUint16(b[6:], 4)
	binary.LittleEndian.PutUint32(b[16:], 65535)
	binary.LittleEndian.PutUint32(b[20:], 1)
	for i, f := range frames {
		h := make([]byte, 16)
		binary.LittleEndian.PutUint32(h, 1000+uint32(i))
		binary.LittleEndian.PutUint32(h[8:], uint32(len(f)))
		binary.LittleEndian.PutUint32(h[12:], uint32(orig[i]))
		b = append(b, h...)
		b = append(b, f...)
	}
	return b
}
func imported(t *testing.T, frames [][]byte, orig []int) (*sqlite.Store, *pcap.ImportResult, learn.GenerateResult) {
	t.Helper()
	s := open(t)
	r, e := pcap.Import(context.Background(), bytes.NewReader(capture(frames, orig)), s, meta(), pcap.AnalysisOptions{}, modbus.NewDecoder())
	check(t, e)
	g := learn.Generator{Store: s, Certifier: &learn.CompilerCertifier{Store: s}}
	out, e := g.Generate(context.Background(), learn.GenerateRequest{DatasetID: r.Dataset.ID})
	check(t, e)
	t.Logf("records=%d truncated=%v gaps=%v losses=%+v suggestions=%d withheld=%v", r.Dataset.Records, r.Stats.Truncated, r.Dataset.Gaps, r.Dataset.Losses, len(out.Suggestions), out.Withheld)
	return s, r, out
}
func TestSnaplenLossOnUnrelatedConnection(t *testing.T) {
	_, _, baseline := imported(t, [][]byte{frame(1, 1)}, []int{66})
	if len(baseline.Suggestions) != 1 {
		t.Fatal("invalid baseline")
	}
	// All L2/L3/L4 headers remain intact; only an unrelated connection's payload is cut.
	_, _, out := imported(t, [][]byte{frame(1, 1), frame(1, 3)[:60]}, []int{66, 66})
	if len(out.Suggestions) != 1 {
		t.Fatal("unrelated localized truncation removed the clean connection")
	}
}
func TestIPTruncationOnSameConnection(t *testing.T) {
	// PCAP lengths agree but the IP total length exposes a truncated TCP payload.
	s, r, out := imported(t, [][]byte{frame(1, 1), frame(13, 1)[:60]}, []int{66, 60})
	assertDirectLoss(t, s, r.Dataset)
	if len(out.Suggestions) != 0 {
		t.Fatal("certified connection with known IP payload truncation")
	}
}

func assertDirectLoss(t *testing.T, s *sqlite.Store, ds evidence.Dataset) {
	t.Helper()
	ctx := context.Background()
	page, err := s.ListObservations(ctx, ds.ID, evidence.PageRequest{})
	check(t, err)
	if len(page.Items) != 1 {
		t.Fatalf("expected earlier complete parent: %+v", page)
	}
	p := page.Items[0]
	rules, reasons := learn.GenerateRelation(p)
	if len(reasons) > 0 {
		t.Fatal(reasons)
	}
	digest, err := evidence.EvidenceDigest([]evidence.Observation{p})
	check(t, err)
	content := learn.SuggestionContent{Versions: learn.Versions{Schema: learn.SuggestionSchemaVersion, Observation: evidence.SchemaVersion, Generator: learn.GeneratorVersion, Evaluator: learn.EvaluatorVersion, Decoder: ds.DecoderVersion, Profile: ds.ProfileFingerprint, Snapshot: ds.SnapshotFingerprint}, EvidenceDigest: digest, Rules: rules}
	_, err = (&learn.CompilerCertifier{Store: s}).Certify(ctx, content, []evidence.EvidenceRef{{DatasetID: ds.ID, ObservationID: p.ID}})
	if err == nil {
		t.Fatal("directly certified loss-affected parent")
	}
}
func TestRecordTruncationScopeFallbacks(t *testing.T) {
	for _, size := range []int{0, 8, 13, 16} {
		t.Run(fmt.Sprintf("unreadable EtherType or VLAN/%d", size), func(t *testing.T) {
			cut := frame(13, 1)[:size]
			if size == 16 {
				binary.BigEndian.PutUint16(cut[12:], 0x8100)
			}
			s, r, out := imported(t, [][]byte{frame(1, 1), cut}, []int{66, 66})
			if len(out.Suggestions) != 0 {
				t.Fatal("unlocalizable record certified", out)
			}
			assertDirectLoss(t, s, r.Dataset)
		})
	}
	t.Run("IP truncation before TCP header completes", func(t *testing.T) {
		_, r, out := imported(t, [][]byte{frame(1, 1), frame(1, 3)[:46]}, []int{66, 46})
		if len(out.Suggestions) != 1 || !r.Stats.Truncated || len(r.Dataset.Losses) != 1 || r.Dataset.Losses[0].Scope.Transport != "tcp" {
			t.Fatal("missing IP bytes were not coordinate scoped", r.Dataset, out)
		}
	})
	t.Run("same connection", func(t *testing.T) {
		s, r, out := imported(t, [][]byte{frame(1, 1), frame(13, 1)[:60]}, []int{66, 66})
		if len(out.Suggestions) != 0 {
			t.Fatal(out)
		}
		assertDirectLoss(t, s, r.Dataset)
	})
	t.Run("unknown tuple", func(t *testing.T) {
		_, r, out := imported(t, [][]byte{frame(1, 1), make([]byte, 30)}, []int{66, 60})
		if len(out.Suggestions) != 1 || len(r.Dataset.Losses) != 1 || r.Dataset.Losses[0].Code != "capture_unrelated" {
			t.Fatal(r.Dataset, out)
		}
	})
	t.Run("malformed complete", func(t *testing.T) {
		bad := frame(13, 1)
		bad[14] = 0x44
		_, r, out := imported(t, [][]byte{frame(1, 1), bad}, []int{66, 66})
		if len(out.Suggestions) != 1 || len(r.Dataset.Losses) != 0 {
			t.Fatal(r.Dataset, out)
		}
	})
	t.Run("headerless final", func(t *testing.T) {
		s := open(t)
		raw := append(capture([][]byte{frame(1, 1)}, []int{66}), 1, 2, 3)
		r, err := pcap.Import(context.Background(), bytes.NewReader(raw), s, meta(), pcap.AnalysisOptions{}, modbus.NewDecoder())
		check(t, err)
		assertDirectLoss(t, s, r.Dataset)
	})
}

func TestWorkshopCaptureKeepsSuggestionsWithUnrelatedCutRecord(t *testing.T) {
	raw, err := os.ReadFile("../../../test/modbus/testdata/operations.pcap")
	check(t, err)
	if binary.LittleEndian.Uint32(raw) != 0xa1b2c3d4 {
		t.Fatal("fixture must be classic little-endian PCAP")
	}
	last := uint32(0)
	for offset := 24; offset+16 <= len(raw); {
		record := raw[offset:]
		last = max(last, binary.LittleEndian.Uint32(record))
		offset += 16 + int(binary.LittleEndian.Uint32(record[8:]))
	}
	header := make([]byte, 16)
	binary.LittleEndian.PutUint32(header, last+1)
	binary.LittleEndian.PutUint32(header[8:], 30)
	binary.LittleEndian.PutUint32(header[12:], 60)
	arp := make([]byte, 30)
	binary.BigEndian.PutUint16(arp[12:], 0x806)
	cut := append(append(append([]byte{}, raw...), header...), arp...)
	baseline := 0
	for _, fixture := range [][]byte{raw, cut} {
		s := open(t)
		r, err := pcap.Import(context.Background(), bytes.NewReader(fixture), s, meta(), pcap.AnalysisOptions{}, modbus.NewDecoder())
		check(t, err)
		g := learn.Generator{Store: s, Certifier: &learn.CompilerCertifier{Store: s}}
		out, err := g.Generate(context.Background(), learn.GenerateRequest{DatasetID: r.Dataset.ID})
		check(t, err)
		t.Logf("workshop: truncated=%v records=%d suggestions=%d withheld=%v", r.Stats.Truncated, r.Dataset.Records, len(out.Suggestions), out.Withheld)
		if baseline == 0 {
			baseline = len(out.Suggestions)
			if baseline == 0 {
				t.Fatal("normal workshop capture is not useful")
			}
		} else if len(out.Suggestions) != baseline {
			t.Fatal("unrelated cut ARP erased workshop suggestions")
		}
	}
}

func TestShortHeaderSameConnection(t *testing.T) {
	for _, size := range []int{34, 36, 38, 46} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			s, r, out := imported(t, [][]byte{frame(1, 1), frame(13, 1)[:size]}, []int{66, size})
			if len(out.Suggestions) != 0 {
				t.Fatal("known loss certified earlier parent", out)
			}
			assertDirectLoss(t, s, r.Dataset)
		})
	}
}

func TestCutNonIPRecordSweep(t *testing.T) {
	raw, err := os.ReadFile("../../../test/modbus/testdata/operations.pcap")
	check(t, err)
	placements := 0
	for offset := 24; offset+16 <= len(raw); {
		record := raw[offset:]
		header := make([]byte, 16)
		copy(header, record[:8])
		binary.LittleEndian.PutUint32(header[8:], 30)
		binary.LittleEndian.PutUint32(header[12:], 120)
		arp := make([]byte, 30)
		binary.BigEndian.PutUint16(arp[12:], 0x806)
		fixture := append(append(append([]byte{}, raw...), header...), arp...)
		s := open(t)
		r, err := pcap.Import(context.Background(), bytes.NewReader(fixture), s, meta(), pcap.AnalysisOptions{}, modbus.NewDecoder())
		check(t, err)
		g := learn.Generator{Store: s, Certifier: &learn.CompilerCertifier{Store: s}}
		out, err := g.Generate(context.Background(), learn.GenerateRequest{DatasetID: r.Dataset.ID})
		check(t, err)
		if len(out.Suggestions) != 15 || len(r.Dataset.Gaps) != 0 || len(r.Dataset.Losses) != 1 || r.Dataset.Losses[0].Code != "capture_unrelated" {
			t.Fatalf("placement %d erased workshop suggestions: %+v %+v", placements, out, r.Dataset)
		}
		check(t, s.Close())
		placements++
		offset += 16 + int(binary.LittleEndian.Uint32(record[8:]))
	}
	t.Logf("all %d cut-ARP placements preserved 15 suggestions", placements)
}

func TestUnrelatedTruncationClassification(t *testing.T) {
	for _, kind := range []string{"VLAN ARP", "stacked VLAN LLDP", "ICMP", "IGMP"} {
		t.Run(kind, func(t *testing.T) {
			cut := frame(13, 1)[:38]
			switch kind {
			case "VLAN ARP":
				binary.BigEndian.PutUint16(cut[12:], 0x8100)
				binary.BigEndian.PutUint16(cut[16:], 0x806)
			case "stacked VLAN LLDP":
				binary.BigEndian.PutUint16(cut[12:], 0x88a8)
				binary.BigEndian.PutUint16(cut[16:], 0x8100)
				binary.BigEndian.PutUint16(cut[20:], 0x88cc)
			case "ICMP":
				cut[23] = 1
			case "IGMP":
				cut[23] = 2
			}
			_, r, out := imported(t, [][]byte{frame(1, 1), cut}, []int{66, 120})
			if len(out.Suggestions) != 1 || len(r.Dataset.Gaps) != 0 || len(r.Dataset.Losses) != 1 || r.Dataset.Losses[0].Code != "capture_unrelated" {
				t.Fatal("unrelated traffic excluded certification inputs", r.Dataset, out)
			}
		})
	}
}

func TestCoordinateLossUsefulness(t *testing.T) {
	for _, size := range []int{34, 38} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			other := frame(1, 1)
			binary.BigEndian.PutUint16(other[34:], 49153)
			_, r, out := imported(t, [][]byte{frame(1, 1), other, frame(13, 1)[:size]}, []int{66, 66, size})
			want := 0 // no ports: either same-host connection may have lost bytes
			if size == 38 {
				want = 1 // intact ports: preserve the other connection
			}
			if len(out.Suggestions) != want || len(r.Dataset.Losses) != 1 || r.Dataset.Losses[0].Scope.Ports != (size == 38) {
				t.Fatal("coordinate precision/usefulness", r.Dataset, out)
			}
		})
	}
}
