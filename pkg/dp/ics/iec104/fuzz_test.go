// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package iec104

import (
	"encoding/json"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields/decodertest"
	"github.com/tonylturner/containd/pkg/dp/internal/corpus"
)

var validKinds = map[string]bool{
	eventfields.KindRequest: true, eventfields.KindResponse: true, eventfields.KindAPCI: true,
	eventfields.KindMalformed: true, eventfields.KindUnsupported: true,
}

// checkEvents enforces the event shape every parse must keep: a known kind,
// one APDU's identity, at most 127 events per APDU, catalogued conformance
// findings, and attributes that marshal to JSON (no NaN or infinite values).
func checkEvents(t *testing.T, res dpi.StreamResult) {
	t.Helper()
	for _, f := range res.Frames {
		if len(f.Events) == 0 || len(f.Events) > 127 {
			t.Fatalf("APDU [%d,%d) has %d events", f.Start, f.End, len(f.Events))
		}
		for _, ev := range f.Events {
			if !validKinds[ev.Kind] || ev.Proto != eventfields.ProtoIEC104 {
				t.Fatalf("event %s/%s", ev.Proto, ev.Kind)
			}
			if _, ok := ev.Attributes[eventfields.KeyAPDUID]; !ok {
				t.Fatalf("event without apdu_id: %v", ev.Attributes)
			}
			_, hasErr := ev.Attributes[eventfields.KeyError]
			if hasErr != (ev.Kind == eventfields.KindMalformed || ev.Kind == eventfields.KindUnsupported) {
				t.Fatalf("%s event error presence %v", ev.Kind, hasErr)
			}
			checkFindings(t, ev)
			if _, err := json.Marshal(ev.Attributes); err != nil {
				t.Fatalf("attributes do not marshal: %v", err)
			}
		}
	}
}

func addFixtureSeeds(f *testing.F) {
	for _, fx := range loadFixtures(f) {
		f.Add(fx.bytes, fx.dir == dpi.ServerToClient)
	}
	for _, fixture := range loadReferenceCaptures(f) {
		seeds := corpus.Seeds(fixture)
		seedIndex := 0
		for _, packet := range fixture.Packets {
			if len(packet.Decoded.Payload) == 0 {
				continue
			}
			f.Add(seeds[seedIndex], packet.Dir == dpi.ServerToClient)
			seedIndex++
		}
		if seedIndex != len(seeds) {
			f.Fatalf("%s yielded %d packet seeds for %d payloads", fixture.Name, len(seeds), seedIndex)
		}
		for _, seed := range captureStreamSeeds(f, fixture) {
			f.Add(seed.bytes, seed.dir == dpi.ServerToClient)
		}
	}
}

// FuzzAPCI checks APCI framing on arbitrary bytes.
func FuzzAPCI(f *testing.F) {
	addFixtureSeeds(f)
	f.Fuzz(func(t *testing.T, b []byte, _ bool) {
		n, err := frameAPDU(b)
		switch {
		case err != nil:
			if n != 0 {
				t.Fatalf("error with length %d", n)
			}
		case n == 0:
			if len(b) >= apciLen && len(b) >= 2+int(b[1]) {
				t.Fatalf("need more with a complete APDU in % x", b)
			}
		default:
			if b[0] != startOctet || n != 2+int(b[1]) || n > len(b) || b[1] < minAPDULength || b[1] > maxAPDULength {
				t.Fatalf("framed %d bytes of % x", n, b)
			}
			if a := decodeAPCI(b[:n]); a.format != "I" && a.format != "S" && a.format != "U" {
				t.Fatalf("format %q", a.format)
			}
		}
	})
}

// FuzzASDU wraps arbitrary ASDU bytes in an I-format APDU.
func FuzzASDU(f *testing.F) {
	for _, fx := range loadFixtures(f) {
		if len(fx.bytes) > apciLen && fx.bytes[2]&0x01 == 0 {
			f.Add(fx.bytes[apciLen:], fx.dir == dpi.ServerToClient)
		}
	}
	for _, fixture := range loadReferenceCaptures(f) {
		// Walk complete wire APDUs, including every APDU of coalesced
		// capture streams; partial APDUs remain stream/APCI seeds.
		for _, seed := range captureStreamSeeds(f, fixture) {
			for b := seed.bytes; len(b) >= apciLen; {
				n := int(b[1]) + 2
				if b[0] != 0x68 || n < apciLen || n > len(b) {
					break
				}
				if n > apciLen && b[2]&0x01 == 0 {
					f.Add(b[apciLen:n], seed.dir == dpi.ServerToClient)
				}
				b = b[n:]
			}
		}
	}
	f.Fuzz(func(t *testing.T, body []byte, server bool) {
		if len(body) > maxAPDULength-minAPDULength {
			return
		}
		dir := dpi.ClientToServer
		if server {
			dir = dpi.ServerToClient
		}
		res := parseOne(t, dir, iFrame(1, 1, body))
		if len(res.Frames) != 1 {
			t.Fatalf("%d frames", len(res.Frames))
		}
		checkEvents(t, res)
	})
}

// FuzzStream checks the stream contract (decodertest.CheckStream: framing,
// consumed prefix, no event from a partial APDU, no retained bytes) and the
// event shape on arbitrary streams.
func FuzzStream(f *testing.F) {
	addFixtureSeeds(f)
	f.Add(cat(clientStream(), serverStream()[:17]), false)
	state := iecState()
	f.Fuzz(func(t *testing.T, b []byte, server bool) {
		dir := dpi.ClientToServer
		if server {
			dir = dpi.ServerToClient
		}
		res, _ := decodertest.CheckStream(t, NewDecoder(), state, view(dir, 12345, b))
		checkEvents(t, res)
		n := 0
		for _, fr := range res.Frames {
			n += len(fr.Events)
		}
		if n > len(b) {
			t.Fatalf("%d events from %d bytes", n, len(b))
		}
	})
}
