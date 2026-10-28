// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package modbus

import (
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields/decodertest"
	"github.com/tonylturner/containd/pkg/dp/internal/corpus"
)

func FuzzParseTCPFrame(f *testing.F) {
	for _, fixture := range modbusCaptures(f) {
		for _, seed := range corpus.Seeds(fixture) {
			f.Add(seed)
		}
	}
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x06,
		0x01,
		0x03,
		0x00, 0x00,
		0x00, 0x02,
	})
	f.Add([]byte{
		0x00, 0x02,
		0x00, 0x00,
		0x00, 0x06,
		0x01,
		0x10,
		0x00, 0x00,
		0x00, 0x01,
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseTCPFrame(data)
	})
}

func FuzzParseStream(f *testing.F) {
	for _, fixture := range modbusCaptures(f) {
		seeds, err := corpus.StreamSeeds(fixture)
		if err != nil {
			f.Fatal(err)
		}
		for _, seed := range seeds {
			f.Add(seed, uint16(0))
		}
	}
	f.Add([]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x02}, uint16(0))
	f.Add([]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x01, 0x83, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x01}, uint16(7))
	f.Add([]byte{0x00, 0x01, 0x00, 0x00, 0xFF, 0xFF, 0x01}, uint16(1))

	state := modbusState()
	f.Fuzz(func(t *testing.T, data []byte, base uint16) {
		decodertest.CheckStream(t, NewDecoder(), state, dpi.StreamView{Session: "fuzz", Base: int64(base), Bytes: data})
	})
}
