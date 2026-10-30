// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

//go:build linux

package pcap

import (
	"encoding/binary"
	"io"
	"time"
)

const (
	pcapVersionMajor = 2
	pcapVersionMinor = 4
)

func writePCAPGlobalHeader(w io.Writer, snaplen uint32) error {
	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header[0:], pcapMagicMicro)
	binary.LittleEndian.PutUint16(header[4:], pcapVersionMajor)
	binary.LittleEndian.PutUint16(header[6:], pcapVersionMinor)
	binary.LittleEndian.PutUint32(header[8:], 0)  // thiszone
	binary.LittleEndian.PutUint32(header[12:], 0) // sigfigs
	binary.LittleEndian.PutUint32(header[16:], snaplen)
	binary.LittleEndian.PutUint32(header[20:], 1) // LINKTYPE_ETHERNET
	_, err := w.Write(header)
	return err
}

func writePCAPPacket(w io.Writer, ts time.Time, data []byte) error {
	rec := make([]byte, 16)
	sec := uint32(ts.Unix())
	usec := uint32(ts.Nanosecond() / 1000)
	binary.LittleEndian.PutUint32(rec[0:], sec)
	binary.LittleEndian.PutUint32(rec[4:], usec)
	binary.LittleEndian.PutUint32(rec[8:], uint32(len(data)))
	binary.LittleEndian.PutUint32(rec[12:], uint32(len(data)))
	if _, err := w.Write(rec); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}
