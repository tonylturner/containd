// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package cip

import (
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields/decodertest"
	"github.com/tonylturner/containd/pkg/dp/internal/corpus"
)

func FuzzParseStream(f *testing.F) {
	for _, fixture := range captureFixtures(f) {
		if fixture.Spec.Transport != "tcp" {
			continue
		}
		seeds, err := corpus.StreamSeeds(fixture)
		if err != nil {
			f.Fatal(err)
		}
		for _, seed := range seeds {
			f.Add(seed)
		}
	}
	f.Add([]byte{})
	f.Add([]byte{0x6f, 0})
	for _, fixture := range streamFixtures() {
		f.Add(fixture.raw)
	}
	f.Add(buildEIPHeader(0x6f, 1, make([]byte, 65535))[:eipHeaderSize])
	var coalesced []byte
	for _, fixture := range streamFixtures() {
		coalesced = append(coalesced, fixture.raw...)
	}
	f.Add(coalesced)
	f.Add(coalesced[:len(coalesced)-1])
	f.Fuzz(func(t *testing.T, data []byte) {
		decodertest.CheckStream(t, NewDecoder(), cipState(), dpi.StreamView{
			Session: "fuzz", Base: 123, Bytes: data,
		})
	})
}

func FuzzParseEIPHeader(f *testing.F) {
	for _, fixture := range captureFixtures(f) {
		for _, seed := range corpus.Seeds(fixture) {
			f.Add(seed)
		}
	}
	valid := buildEIPHeader(0x006F, 0x12345678, buildSendRRDataPayload(0x4C, 1, []byte{0x20, 0x02}))

	f.Add([]byte{})
	f.Add([]byte{0x6F, 0x00})
	f.Add(valid)

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseEIPHeader(data)
	})
}

func FuzzParseCIPMessage(f *testing.F) {
	for _, fixture := range captureFixtures(f) {
		if fixture.Spec.Transport != "tcp" {
			continue
		}
		streams, err := corpus.StreamSeeds(fixture)
		if err != nil {
			f.Fatal(err)
		}
		for _, stream := range streams {
			for len(stream) > 0 {
				hdr, err := frameEncapsulation(stream)
				if err != nil || hdr == nil {
					f.Fatalf("capture encapsulation: %v", err)
				}
				if cipCommands[hdr.Command] {
					f.Add(hdr.Data)
				}
				stream = stream[eipHeaderSize+int(hdr.Length):]
			}
		}
	}
	readTag := buildSendRRDataPayload(0x4C, 1, []byte{0x20, 0x02})
	response := cpfMessage(0xcc, 0, 0, 0)
	msp := buildSendRRDataPayload(0x0A, 1, []byte{0x20, 0x02})

	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add(readTag)
	f.Add(response)
	f.Add(msp)
	f.Add(buildCPFItems(cpfTestItem{0x00a1, []byte{1, 0, 0, 0}}, cpfTestItem{0x00b1, []byte{1, 0, 0x4c, 0}}))
	f.Add(buildCPFItems(cpfTestItem{0x00b2, []byte{0x4c, 0}}, cpfTestItem{0x1234, []byte{1}}))

	f.Fuzz(func(t *testing.T, data []byte) {
		_ = ParseCIPMessage(data)
		_ = ParseMSPServices(data)
		_ = ParseEPath(data)
	})
}
