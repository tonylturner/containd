// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package iec104

import (
	"bufio"
	"encoding/hex"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
)

type fixture struct {
	name  string
	dir   dpi.StreamDir
	kinds []string // nil for frame_error
	bytes []byte
}

// loadFixtures reads testdata/synthetic.tsv (format in its header).
func loadFixtures(tb testing.TB) []fixture {
	tb.Helper()
	f, err := os.Open("testdata/synthetic.tsv")
	if err != nil {
		tb.Fatalf("open fixtures: %v", err)
	}
	defer f.Close()
	var out []fixture
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) != 5 {
			tb.Fatalf("fixture line %q: %d columns", line, len(cols))
		}
		b, err := hex.DecodeString(cols[3])
		if err != nil {
			tb.Fatalf("fixture %s: %v", cols[0], err)
		}
		fx := fixture{name: cols[0], dir: dpi.ClientToServer, bytes: b}
		if cols[1] == "s" {
			fx.dir = dpi.ServerToClient
		}
		if cols[2] != "frame_error" {
			fx.kinds = strings.Split(cols[2], ",")
		}
		out = append(out, fx)
	}
	if err := sc.Err(); err != nil {
		tb.Fatalf("read fixtures: %v", err)
	}
	return out
}

func TestSyntheticFixtures(t *testing.T) {
	fixtures := loadFixtures(t)
	if len(fixtures) < 40 {
		t.Fatalf("only %d fixtures", len(fixtures))
	}
	var stream []byte
	for _, fx := range fixtures {
		res, err := NewDecoder().ParseStream(iecState(), view(fx.dir, 0, fx.bytes))
		if fx.kinds == nil {
			var fe *dpi.FrameError
			if !errors.As(err, &fe) || fe.Offset != 0 {
				t.Errorf("%s: err = %v, want FrameError at 0", fx.name, err)
			}
			continue
		}
		if err != nil || len(res.Frames) != 1 || res.Consumed != len(fx.bytes) {
			t.Errorf("%s: err %v frames %d consumed %d", fx.name, err, len(res.Frames), res.Consumed)
			continue
		}
		var kinds []string
		for _, ev := range res.Frames[0].Events {
			kinds = append(kinds, ev.Kind)
		}
		if !reflect.DeepEqual(kinds, fx.kinds) {
			t.Errorf("%s: kinds %v, want %v (%v)", fx.name, kinds, fx.kinds, res.Frames[0].Events[0].Attributes["error"])
		}
		if fx.dir == dpi.ClientToServer {
			stream = append(stream, fx.bytes...)
		}
	}
	// Every complete client fixture back to back in one view.
	res, err := NewDecoder().ParseStream(iecState(), view(dpi.ClientToServer, 0, stream))
	if err != nil || res.Consumed != len(stream) {
		t.Fatalf("coalesced client fixtures: err %v consumed %d of %d", err, res.Consumed, len(stream))
	}
}
