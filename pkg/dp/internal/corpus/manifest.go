// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package corpus

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"
	"unicode"

	"github.com/tonylturner/containd/pkg/dp/ics"
)

// Manifest is schema version 1. Provenance values are descriptive evidence,
// not assertions that this helper can certify third-party generation.
type Manifest struct {
	Version    int               `json:"version"`
	Protocol   string            `json:"protocol"`
	Provenance map[string]string `json:"provenance"`
	Scenarios  []Scenario        `json:"scenarios"`
}
type Scenario struct {
	Name             string   `json:"name"`
	PCAP             string   `json:"pcap"`
	Oracle           string   `json:"oracle"`
	Expectations     string   `json:"expectations"`
	Assets           []string `json:"assets,omitempty"`
	Transport        string   `json:"transport"`
	Roles            []Role   `json:"roles,omitempty"`
	AllowMidstream   bool     `json:"allow_midstream,omitempty"`
	Contiguous       bool     `json:"contiguous"`
	OracleFrames     []int    `json:"oracle_frames"`
	UnobservedFrames []int    `json:"unobserved_frames,omitempty"`
	IgnoreEtherTypes []uint16 `json:"ignore_ethertypes,omitempty"`
	ChecksumOffload  string   `json:"checksum_offload"`
}

// Fixture retains pristine capture records, independent observations, and
// separate protocol-owned coverage/finding declarations. Derived fixtures
// retain the originals' Oracle and use Source spans for attribution.
type Fixture struct {
	Name         string
	Manifest     Manifest
	Spec         Scenario
	Packets      []Packet
	Skipped      []SkippedRecord
	Oracle       []OracleRow
	Expectations map[string]json.RawMessage
	Derived      []string
}

func readFile(fsys fs.FS, name string, max int64) ([]byte, error) {
	if !fs.ValidPath(name) {
		return nil, fmt.Errorf("invalid path %q", name)
	}
	// Reject symlinks in every component, including under os.DirFS.
	dir := "."
	for _, part := range strings.Split(name, "/") {
		entries, err := fs.ReadDir(fsys, dir)
		if err != nil {
			return nil, err
		}
		found := false
		for _, e := range entries {
			if e.Name() == part {
				found = true
				if e.Type()&fs.ModeSymlink != 0 {
					return nil, fmt.Errorf("symlink path %q", name)
				}
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("missing %q", name)
		}
		dir = path.Join(dir, part)
	}
	f, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > max {
		return nil, fmt.Errorf("file %q exceeds bounds or is not regular", name)
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("file %q exceeds bounds", name)
	}
	return b, nil
}
func strictJSON(b []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}
func fileName(s string) bool {
	return s != "." && fs.ValidPath(s) && !strings.Contains(s, "/") && !strings.Contains(s, "\\") && strings.IndexFunc(s, unicode.IsSpace) < 0
}

// Load authenticates all pcaps, oracle tables, expectation files and assets
// before reading them. SHA256SUMS must contain exactly these referenced files;
// neither SHA256SUMS nor manifest.json is self-hashed.
func Load(fsys fs.FS, manifestPath string) ([]Fixture, error) {
	b, err := readFile(fsys, manifestPath, 1<<20)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := strictJSON(b, &m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if m.Version != 1 || len(m.Scenarios) == 0 || len(m.Scenarios) > 1000 {
		return nil, fmt.Errorf("invalid manifest version or scenarios")
	}
	for _, key := range []string{"source", "generator", "oracle", "license", "topology", "capture_side"} {
		if strings.TrimSpace(m.Provenance[key]) == "" {
			return nil, fmt.Errorf("missing provenance %s", key)
		}
	}
	known := false
	for _, p := range ics.DecoderPorts() {
		if p.Protocol == m.Protocol {
			known = true
		}
	}
	if !known {
		return nil, fmt.Errorf("unknown protocol %q", m.Protocol)
	}
	files := map[string]int64{}
	names := map[string]bool{}
	for _, s := range m.Scenarios {
		if !fileName(s.Name) || names[s.Name] || s.ChecksumOffload == "" {
			return nil, fmt.Errorf("empty/duplicate scenario or missing checksum disclosure")
		}
		names[s.Name] = true
		if s.Transport != "tcp" && s.Transport != "udp" {
			return nil, fmt.Errorf("invalid transport")
		}
		for index, n := range append([]string{s.PCAP, s.Oracle, s.Expectations}, s.Assets...) {
			if !fileName(n) || files[n] != 0 || n == path.Base(manifestPath) || n == "SHA256SUMS" {
				return nil, fmt.Errorf("invalid/duplicate file %q", n)
			}
			limit := int64(MaxCaptureBytes)
			if index == 1 {
				limit = 8 << 20
			}
			if index == 2 {
				limit = 1 << 20
			}
			files[n] = limit
		}
	}
	base := path.Dir(manifestPath)
	sums, err := readFile(fsys, path.Join(base, "SHA256SUMS"), 1<<20)
	if err != nil {
		return nil, err
	}
	hashes, err := parseSums(sums)
	if err != nil {
		return nil, err
	}
	if len(hashes) != len(files) {
		return nil, fmt.Errorf("checksum inventory mismatch")
	}
	data := map[string][]byte{}
	total := 0
	for name, limit := range files {
		want, ok := hashes[name]
		if !ok {
			return nil, fmt.Errorf("missing checksum %s", name)
		}
		v, err := readFile(fsys, path.Join(base, name), limit)
		if err != nil {
			return nil, err
		}
		total += len(v)
		if total > 128<<20 {
			return nil, fmt.Errorf("fixture inventory exceeds bounds")
		}
		sum := sha256.Sum256(v)
		if hex.EncodeToString(sum[:]) != want {
			return nil, fmt.Errorf("checksum mismatch %s", name)
		}
		data[name] = v
	}
	var fixtures []Fixture
	for _, s := range m.Scenarios {
		f := Fixture{Name: s.Name, Manifest: m, Spec: s}
		packets, skipped, err := ReadPCAP(bytes.NewReader(data[s.PCAP]), s.PCAP, ReadOptions{IgnoreEtherTypes: s.IgnoreEtherTypes})
		if err != nil {
			return nil, err
		}
		f.Skipped = skipped
		for _, p := range packets {
			selected := false
			for _, port := range ics.DecoderPorts() {
				if port.Protocol == m.Protocol && port.Transport == p.Decoded.Proto && p.Decoded.Transport == s.Transport && (port.Port == p.Decoded.SrcPort || port.Port == p.Decoded.DstPort) {
					selected = true
				}
			}
			if selected {
				f.Packets = append(f.Packets, p)
			} else {
				f.Skipped = append(f.Skipped, SkippedRecord{p.Source[0].Frame, "outside declared protocol/transport"})
			}
		}
		if len(f.Packets) == 0 {
			return nil, fmt.Errorf("scenario %s selects no records", s.Name)
		}
		if err := orient(&f); err != nil {
			return nil, fmt.Errorf("scenario %s: %w", s.Name, err)
		}
		f.Oracle, err = ReadOracle(bytes.NewReader(data[s.Oracle]), s.PCAP)
		if err != nil {
			return nil, err
		}
		if err := validateOracle(f); err != nil {
			return nil, err
		}
		if err := strictJSON(data[s.Expectations], &f.Expectations); err != nil || len(f.Expectations) == 0 {
			return nil, fmt.Errorf("invalid/empty expectations %s: %v", s.Expectations, err)
		}
		fixtures = append(fixtures, f)
	}
	return fixtures, nil
}
func parseSums(b []byte) (map[string]string, error) {
	out := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		if len(line) < 67 || line[64] != ' ' || (line[65] != ' ' && line[65] != '*') {
			return nil, fmt.Errorf("invalid SHA256SUMS row")
		}
		hash, name := line[:64], line[66:]
		v, err := hex.DecodeString(hash)
		if err != nil || len(v) != 32 || hash != strings.ToLower(hash) || !fileName(name) || out[name] != "" {
			return nil, fmt.Errorf("invalid/duplicate checksum %q", name)
		}
		out[name] = hash
	}
	return out, nil
}
