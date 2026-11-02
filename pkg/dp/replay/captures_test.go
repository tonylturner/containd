// SPDX-License-Identifier: Apache-2.0

package replay

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// installedSet stages the image layout in a test-owned temporary directory;
// the repository contains only references, never duplicated capture bytes.
func installedSet(t *testing.T) (string, *CaptureSet) {
	t.Helper()
	root := "../../.."
	manifest, err := os.ReadFile(filepath.Join(root, "test/demo/manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifestSet CaptureSet
	if err := json.Unmarshal(manifest, &manifestSet); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "manifest.json"), manifest)
	for _, cap := range manifestSet.Captures {
		data, err := os.ReadFile(filepath.Join(root, cap.File))
		if err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, filepath.Join(dir, cap.File), data)
	}
	set, err := LoadCaptureSet(dir)
	if err != nil {
		t.Fatal(err)
	}
	return dir, set
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestManifestDecodesAndMatchesAuthority(t *testing.T) {
	_, set := installedSet(t)
	if len(set.Captures) != 38 {
		t.Fatalf("captures=%d", len(set.Captures))
	}
	mutations := 0
	frames := 0
	for _, cap := range set.Captures {
		if strings.Contains(cap.File, "identify") {
			t.Fatalf("synthetic fixture: %s", cap.File)
		}
		sums, err := os.ReadFile(filepath.Join("../../..", filepath.Dir(cap.File), "SHA256SUMS"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(sums, []byte(cap.SHA256+"  "+filepath.Base(cap.File))) {
			t.Fatalf("%s hash not in SHA256SUMS", cap.File)
		}
		if cap.Mutated {
			mutations++
		}
		for _, rec := range cap.records {
			frames++
			if rec.packet.IPVersion != 4 || !rec.packet.PortsValid || rec.origLen <= rec.ipLen {
				t.Fatalf("%s invalid record %+v", cap.File, rec)
			}
		}
	}
	if mutations != 8 || frames != 1543 {
		t.Fatalf("mutated=%d frames=%d", mutations, frames)
	}
}

func TestLoadCaptureSetFailuresAreAtomic(t *testing.T) {
	dir, set := installedSet(t)
	// Fail at the last recording, after all preceding files were verified.
	last := set.Captures[len(set.Captures)-1]
	for _, tc := range []struct {
		name string
		edit func(*CaptureSet)
		want string
	}{
		{"missing", func(s *CaptureSet) { s.Captures[len(s.Captures)-1].File += ".missing" }, last.File + ".missing"},
		{"hash", func(s *CaptureSet) {
			old := s.Captures[len(s.Captures)-1].SHA256
			replacement := "0"
			if old[:1] == replacement {
				replacement = "1"
			}
			s.Captures[len(s.Captures)-1].SHA256 = replacement + old[1:]
		}, last.File + ": sha256 mismatch"},
		{"path", func(s *CaptureSet) { s.Captures[0].File = "../escape" }, "../escape"},
		{"version", func(s *CaptureSet) { s.Version++ }, "version"},
		{"empty", func(s *CaptureSet) { s.Captures = nil }, "empty"},
		{"duplicate", func(s *CaptureSet) { s.Captures = append(s.Captures, s.Captures[0]) }, "duplicate"},
		{"roles", func(s *CaptureSet) { s.Captures[0].Roles = nil }, "roles"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cloned, err := json.Marshal(set)
			if err != nil {
				t.Fatal(err)
			}
			var changed CaptureSet
			if err := json.Unmarshal(cloned, &changed); err != nil {
				t.Fatal(err)
			}
			tc.edit(&changed)
			data, err := json.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, filepath.Join(dir, "manifest.json"), data)
			got, err := LoadCaptureSet(dir)
			if got != nil || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("partial=%v err=%v want=%s", got != nil, err, tc.want)
			}
		})
	}
}

func TestLoadCaptureSetMissingManifest(t *testing.T) {
	if got, err := LoadCaptureSet(t.TempDir()); got != nil || err == nil || !strings.Contains(err.Error(), "manifest.json") {
		t.Fatalf("got=%v err=%v", got, err)
	}
}
