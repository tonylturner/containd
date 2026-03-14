// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package bacnet

import (
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
)

func FuzzParseFrame(f *testing.F) {
	readProperty := []byte{
		0x81, 0x0A, 0x00, 0x11,
		0x01, 0x00,
		0x00, 0x05, 0x01, 0x0C,
		0x0C, 0x02, 0x00, 0x00, 0x01, 0x19, 0x55,
	}
	whoIs := []byte{
		0x81, 0x0B, 0x00, 0x08,
		0x01, 0x00,
		0x10, 0x08,
	}

	f.Add([]byte{})
	f.Add([]byte{0x81})
	f.Add(readProperty)
	f.Add(whoIs)

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseFrame(data)
	})
}

func FuzzDecoderOnPacket(f *testing.F) {
	dec := NewDecoder()
	state := flow.NewState(keyFor("10.0.0.1", "10.0.0.2", 47808, 47808), time.Now())

	f.Add([]byte{})
	f.Add([]byte{0x81, 0x0A, 0x00, 0x04})
	f.Add([]byte{
		0x81, 0x0A, 0x00, 0x0C,
		0x01, 0x00,
		0x00, 0x05, 0x01, 0x0F,
		0xAA, 0xBB,
	})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = dec.OnPacket(state, &dpi.ParsedPacket{Payload: data})
	})
}
