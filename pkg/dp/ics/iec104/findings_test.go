// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package iec104

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields/decodertest"
)

// checkFindings enforces the finding contract on one event: a malformed or
// unsupported event carries at least one code, and every code list is
// sorted, unique and drawn from the catalogue.
func checkFindings(t *testing.T, ev dpi.Event) {
	t.Helper()
	codes, _ := eventfields.Strings(ev.Attributes, eventfields.KeyConformance)
	if _, present := ev.Attributes[eventfields.KeyConformance]; present && len(codes) == 0 {
		t.Fatalf("%s event with an empty conformance list", ev.Kind)
	}
	if (ev.Kind == eventfields.KindMalformed || ev.Kind == eventfields.KindUnsupported) && len(codes) == 0 {
		t.Fatalf("%s event without a finding: %v", ev.Kind, ev.Attributes[eventfields.KeyError])
	}
	if !slices.IsSorted(codes) || len(slices.Compact(slices.Clone(codes))) != len(codes) {
		t.Fatalf("findings not sorted and unique: %v", codes)
	}
	for _, code := range codes {
		if !strings.HasPrefix(code, "iec104.") || !slices.Contains(Findings, code) {
			t.Fatalf("finding %q is not in the catalogue", code)
		}
	}
}

// Every catalogued finding is produced by some APDU, and a frame error
// (lost boundary) never carries one.
func TestFindingsCatalogue(t *testing.T) {
	if !slices.IsSorted(Findings) || len(slices.Compact(slices.Clone(Findings))) != len(Findings) {
		t.Fatalf("catalogue is not sorted and unique: %v", Findings)
	}
	produced := map[string]bool{}
	frames := []struct {
		dir   dpi.StreamDir
		frame []byte
	}{
		{cli, []byte{0x68, 4, 0x01, 0x00, 0x05, 0x00}},
		{cli, []byte{0x68, 4, 0x47, 0, 0, 0}},
		{cli, []byte{0x68, 5, 0x43, 0, 0, 0, 0xCC}},
		{cli, iFrame(0, 0, nil)},
		{srv, iFrame(0, 0, asdu(2, 1, cotSpont, 0, 1, cat(ioa(1), []byte{1})...))},
		{cli, iFrame(0, 0, asdu(3, 1, cotSpont, 0, 1, cat(ioa(1), []byte{1})...))},
		{cli, iFrame(0, 0, asdu(100, 0, cotAct, 0, 1))},
		{cli, iFrame(0, 0, asdu(46, 2, cotAct, 0, 1, cat(ioa(1), []byte{1}, ioa(2), []byte{1})...))},
		{srv, iFrame(0, 0, asdu(1, 1, cotSpont, 0, 1, ioa(1)...))},
		{srv, iFrame(0, 0, asdu(3, vsqSQ|2, cotSpont, 0, 1, cat(ioa(16777215), []byte{1, 1})...))},
		{cli, iFrame(0, 0, asdu(46, 1, cotAct, 0, 1, cat(ioa(1), []byte{0x80})...))},
		{srv, iFrame(0, 0, asdu(31, 1, cotSpont, 0, 1, cat(ioa(1), []byte{1}, cp56(25, 2, 29, 0, 0, 0))...))},
	}
	for _, f := range frames {
		for _, ev := range events(parseOne(t, f.dir, f.frame)) {
			checkFindings(t, ev)
			codes, _ := eventfields.Strings(ev.Attributes, eventfields.KeyConformance)
			for _, code := range codes {
				produced[code] = true
			}
			for form, attrs := range decodertest.Forms(t, ev.Attributes) {
				if got, _ := eventfields.Strings(attrs, eventfields.KeyConformance); !slices.Equal(got, codes) {
					t.Fatalf("%s form lost findings: %v != %v", form, got, codes)
				}
			}
		}
	}
	for _, code := range Findings {
		if !produced[code] {
			t.Errorf("no fixture produces %s", code)
		}
	}
	_, err := NewDecoder().ParseStream(iecState(), view(cli, 0, []byte{0x69, 4, 0x07, 0, 0, 0}))
	var fe *dpi.FrameError
	if !errors.As(err, &fe) {
		t.Fatalf("lost boundary did not frame-error: %v", err)
	}
	if _, present := fe.Event.Attributes[eventfields.KeyConformance]; present {
		t.Fatalf("frame error carries findings: %v", fe.Event.Attributes)
	}
}

// A conformant stream carries no conformance attribute at all.
func TestConformantStreamHasNoFindings(t *testing.T) {
	for _, ev := range events(parseOne(t, cli, clientStream())) {
		if _, present := ev.Attributes[eventfields.KeyConformance]; present {
			t.Fatalf("conformant event carries findings: %v", ev.Attributes)
		}
	}
	for _, ev := range events(parseOne(t, srv, serverStream())) {
		checkFindings(t, ev)
	}
}
