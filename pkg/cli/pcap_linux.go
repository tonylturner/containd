// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package cli

import (
	"encoding/binary"
	"io"
	"time"
)

func writePCAPGlobalHeader(w io.Writer, snaplen uint32) error {
	type hdr struct {
		Magic        uint32
		VersionMajor uint16
		VersionMinor uint16
		ThisZone     int32
		SigFigs      uint32
		SnapLen      uint32
		Network      uint32
	}
	h := hdr{
		Magic:        0xa1b2c3d4,
		VersionMajor: 2,
		VersionMinor: 4,
		SnapLen:      snaplen,
		Network:      1, // LINKTYPE_ETHERNET
	}
	return binary.Write(w, binary.LittleEndian, h)
}

func writePCAPPacket(w io.Writer, ts time.Time, data []byte) error {
	type rec struct {
		TsSec   uint32
		TsUsec  uint32
		InclLen uint32
		OrigLen uint32
	}
	r := rec{
		TsSec:   uint32(ts.Unix()),
		TsUsec:  uint32(ts.Nanosecond() / 1000),
		InclLen: uint32(len(data)),
		OrigLen: uint32(len(data)),
	}
	if err := binary.Write(w, binary.LittleEndian, r); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}
