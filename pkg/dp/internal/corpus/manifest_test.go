// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package corpus

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/tonylturner/containd/pkg/dp/capture"
)

func tinyFS(t *testing.T) fstest.MapFS {
	t.Helper()
	m := Manifest{Version: 1, Protocol: "modbus", Provenance: map[string]string{"source": "independent fake", "generator": "unit test", "oracle": "synthetic TSV", "license": "Apache-2.0", "topology": "two endpoints", "capture_side": "client"}, Scenarios: []Scenario{{Name: "tiny", PCAP: "tiny.pcap", Oracle: "tiny.expected.tsv", Expectations: "tiny.expectations.json", Transport: "tcp", Contiguous: true, OracleFrames: []int{2}, ChecksumOffload: "none"}}}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	files := fstest.MapFS{
		"manifest.json":          {Data: b},
		"tiny.pcap":              {Data: pcap(binary.LittleEndian, false, wire(6, 99, capture.TCPFlagSYN, "", false), wire(6, 100, capture.TCPFlagACK, "abcd", false))},
		"tiny.expected.tsv":      {Data: []byte("frame.number\tpdu\tobject\ttcp.payload\tfake.field\n2\t0\t0\t61626364\t0\n2\t0\t1\t61:62:63:64\t\n")},
		"tiny.expectations.json": {Data: []byte(`{"coverage":"complete","tail":"none"}`)},
	}
	rehash(files)
	return files
}
func rehash(files fstest.MapFS) {
	var b strings.Builder
	for _, n := range []string{"tiny.pcap", "tiny.expected.tsv", "tiny.expectations.json"} {
		fmt.Fprintf(&b, "%x  %s\n", sha256.Sum256(files[n].Data), n)
	}
	files["SHA256SUMS"] = &fstest.MapFile{Data: []byte(b.String())}
}
func editManifest(t *testing.T, files fstest.MapFS, fn func(*Manifest)) {
	t.Helper()
	var m Manifest
	if err := json.Unmarshal(files["manifest.json"].Data, &m); err != nil {
		t.Fatal(err)
	}
	fn(&m)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	files["manifest.json"].Data = b
}
func TestManifestLoad(t *testing.T) {
	files := tinyFS(t)
	fixtures, err := Load(files, "manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	f := fixtures[0]
	if len(fixtures) != 1 || len(f.Oracle) != 2 || f.Oracle[1].Object != 1 || f.Oracle[0].Fields["fake.field"] != "0" || f.Oracle[1].Fields["fake.field"] != "" || !f.Packets[1].HasOrigin || f.Packets[1].Origin != 100 {
		t.Fatalf("lost metadata: %+v", f)
	}
	// The same loader works below an fs root, not just at its top level.
	nested := fstest.MapFS{}
	for k, v := range files {
		nested["data/"+k] = v
	}
	if _, err := Load(nested, "data/manifest.json"); err != nil {
		t.Fatal(err)
	}
}
func TestManifestReject(t *testing.T) {
	cases := map[string]func(fstest.MapFS){
		"hash":              func(f fstest.MapFS) { f["tiny.pcap"].Data[10]++ },
		"oracle-hash":       func(f fstest.MapFS) { f["tiny.expected.tsv"].Data[0]++ },
		"expectation-hash":  func(f fstest.MapFS) { f["tiny.expectations.json"].Data[0]++ },
		"duplicate-sums":    func(f fstest.MapFS) { f["SHA256SUMS"].Data = append(f["SHA256SUMS"].Data, f["SHA256SUMS"].Data...) },
		"missing-sums":      func(f fstest.MapFS) { delete(f, "SHA256SUMS") },
		"symlink":           func(f fstest.MapFS) { f["tiny.pcap"].Mode = fs.ModeSymlink },
		"expectation-empty": func(f fstest.MapFS) { f["tiny.expectations.json"].Data = []byte("{}"); rehash(f) },
		"expectation-json":  func(f fstest.MapFS) { f["tiny.expectations.json"].Data = []byte("{bad}"); rehash(f) },
		"oracle-payload": func(f fstest.MapFS) {
			f["tiny.expected.tsv"].Data = bytes.ReplaceAll(f["tiny.expected.tsv"].Data, []byte("61626364"), []byte("71626364"))
			rehash(f)
		},
		"oracle-missing": func(f fstest.MapFS) {
			f["tiny.expected.tsv"].Data = []byte("frame.number\ttcp.payload\n1\t\n")
			rehash(f)
		},
	}
	for name, fn := range cases {
		t.Run(name, func(t *testing.T) {
			f := tinyFS(t)
			fn(f)
			if _, err := Load(f, "manifest.json"); err == nil {
				t.Fatal("accepted invalid fixture")
			}
		})
	}
	manifestCases := map[string]func(*Manifest){
		"version":            func(m *Manifest) { m.Version++ },
		"empty":              func(m *Manifest) { m.Scenarios = nil },
		"duplicate":          func(m *Manifest) { m.Scenarios = append(m.Scenarios, m.Scenarios[0]) },
		"traversal":          func(m *Manifest) { m.Scenarios[0].PCAP = "../tiny.pcap" },
		"missing-provenance": func(m *Manifest) { delete(m.Provenance, "license") },
		"protocol":           func(m *Manifest) { m.Protocol = "fake" },
		"transport":          func(m *Manifest) { m.Scenarios[0].Transport = "udp" },
		"unobserved-overlap": func(m *Manifest) { m.Scenarios[0].UnobservedFrames = []int{2} },
		"duplicate-frame":    func(m *Manifest) { m.Scenarios[0].OracleFrames = []int{2, 2} },
		"missing-frame":      func(m *Manifest) { m.Scenarios[0].OracleFrames = []int{3} },
		"undeclared-frame":   func(m *Manifest) { m.Scenarios[0].OracleFrames = nil },
	}
	for name, fn := range manifestCases {
		t.Run(name, func(t *testing.T) {
			f := tinyFS(t)
			editManifest(t, f, fn)
			if _, err := Load(f, "manifest.json"); err == nil {
				t.Fatal("accepted invalid manifest")
			}
		})
	}
	f := tinyFS(t)
	if _, err := Load(f, "../manifest.json"); err == nil {
		t.Fatal("accepted manifest traversal")
	}
	f["manifest.json"].Data = append(f["manifest.json"].Data, []byte(" {}")...)
	if _, err := Load(f, "manifest.json"); err == nil {
		t.Fatal("accepted trailing JSON")
	}
}
func TestOracleReject(t *testing.T) {
	for _, s := range []string{
		"frame.number\tframe.number\ttcp.payload\n1\t1\t00\n",
		"frame.number\ttcp.payload\n0\t00\n",
		"frame.number\ttcp.payload\n1\txx\n",
		"frame.number\ttcp.payload\n1\t00\textra\n",
		"frame.number\ttcp.payload\n1\t00\n1\t00\n",
		"frame.number\ttcp.payload\tpdu\n1\t00\t-1\n",
		"frame.number\ttcp.payload\n",
		"frame.number\n1\n",
	} {
		if _, err := ReadOracle(strings.NewReader(s), "tiny"); err == nil {
			t.Fatalf("accepted %q", s)
		}
	}
}
