// SPDX-License-Identifier: Apache-2.0

package replay

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestPackagedCaptureAllowlist(t *testing.T) {
	_, set := installedSet(t)
	want := []string{"test/demo/manifest.json", "test/demo/NOTICE"}
	families := map[string]bool{}
	for _, cap := range set.Captures {
		want = append(want, cap.File)
		families[cap.Family] = true
	}
	for family := range families {
		want = append(want, "test/"+family+"/testdata/LICENSE")
	}
	slices.Sort(want)
	ignore, err := os.ReadFile("../../../.dockerignore")
	if err != nil {
		t.Fatal(err)
	}
	var allowed []string
	for line := range strings.SplitSeq(string(ignore), "\n") {
		if strings.HasPrefix(line, "!test/") && filepath.Ext(line) != "" || strings.HasPrefix(line, "!test/") && (strings.HasSuffix(line, "/LICENSE") || strings.HasSuffix(line, "/NOTICE")) {
			allowed = append(allowed, strings.TrimPrefix(line, "!"))
		}
	}
	slices.Sort(allowed)
	if !reflect.DeepEqual(allowed, want) {
		t.Fatalf("Docker context allowlist drift:\ngot %v\nwant %v", allowed, want)
	}
	for _, file := range []string{"build/Dockerfile.engine", "build/Dockerfile.mgmt"} {
		raw, err := os.ReadFile("../../../" + file)
		if err != nil {
			t.Fatal(err)
		}
		var copied []string
		for line := range strings.SplitSeq(strings.ReplaceAll(string(raw), "\\\n", ""), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 3 || fields[0] != "COPY" || !strings.HasPrefix(fields[1], "test/") {
				continue
			}
			dest := fields[len(fields)-1]
			for _, src := range fields[1 : len(fields)-1] {
				copied = append(copied, src)
				if !strings.Contains(src, "test/demo/") && dest != "/usr/share/containd/demo/"+filepath.Dir(src)+"/" {
					t.Fatalf("%s flattens manifest path %s into %s", file, src, dest)
				}
				if strings.Contains(src, "test/demo/") && dest != "/usr/share/containd/demo/" {
					t.Fatalf("%s installs manifest/NOTICE outside demo root", file)
				}
			}
		}
		slices.Sort(copied)
		if !reflect.DeepEqual(copied, want) {
			t.Fatalf("%s copy drift:\ngot %v\nwant %v", file, copied, want)
		}
	}
}
