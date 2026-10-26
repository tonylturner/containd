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
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
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

func TestNewMonitorTypesRejectBadLengths(t *testing.T) {
	types := map[byte]bool{
		5: true, 7: true, 9: true, 11: true, 15: true, 21: true,
		32: true, 33: true, 34: true, 35: true, 36: true, 37: true,
	}
	seen := make(map[byte]bool, len(types))
	for _, fx := range loadFixtures(t) {
		if len(fx.bytes) < 7 || !types[fx.bytes[6]] {
			continue
		}
		typeID := fx.bytes[6]
		seen[typeID] = true
		for _, delta := range []int{-1, 1} {
			bad := append([]byte(nil), fx.bytes...)
			if delta < 0 {
				bad = bad[:len(bad)-1]
			} else {
				bad = append(bad, 0)
			}
			bad[1] = byte(len(bad) - 2)
			res := parseOne(t, dpi.ServerToClient, bad)
			evs := events(res)
			if len(evs) != 1 || evs[0].Kind != eventfields.KindMalformed {
				t.Errorf("type %d length delta %+d: got %d events, want malformed", typeID, delta, len(evs))
				continue
			}
			if !strings.Contains(evs[0].Attributes[eventfields.KeyError].(string), "ASDU body is") {
				t.Errorf("type %d length delta %+d: error = %v", typeID, delta, evs[0].Attributes[eventfields.KeyError])
			}
		}
	}
	for typeID := range types {
		if !seen[typeID] {
			t.Errorf("no synthetic decoder fixture for monitor type %d", typeID)
		}
	}
}
