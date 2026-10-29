// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

package pcap

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

func makePCAPRecord(inclLen uint32, payload []byte) []byte {
	rec := make([]byte, 16)
	binary.LittleEndian.PutUint32(rec[8:], inclLen)
	binary.LittleEndian.PutUint32(rec[12:], inclLen)
	return append(rec, payload...)
}

func TestReadPCAPPacketRejectsLengthAboveSnaplen(t *testing.T) {
	data := makePCAPRecord(128, nil)
	reader := &pcapReader{r: bytes.NewReader(data), order: binary.LittleEndian, tick: time.Microsecond, snaplen: 64}
	_, _, _, err := reader.readRecord()
	if err == nil {
		t.Fatal("expected error for packet length above snaplen")
	}
	if !strings.Contains(err.Error(), "exceeds snaplen") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReadPCAPPacketRejectsLengthAboveMaximum(t *testing.T) {
	data := makePCAPRecord(maxPCAPRecordSize+1, nil)
	reader := &pcapReader{r: bytes.NewReader(data), order: binary.LittleEndian, tick: time.Microsecond, snaplen: maxPCAPRecordSize + 1}
	_, _, _, err := reader.readRecord()
	if err == nil {
		t.Fatal("expected error for packet length above max")
	}
	if !strings.Contains(err.Error(), "exceeds maximum") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReadPCAPPacketAcceptsValidLength(t *testing.T) {
	payload := []byte{1, 2, 3, 4}
	data := makePCAPRecord(uint32(len(payload)), payload)
	reader := &pcapReader{r: bytes.NewReader(data), order: binary.LittleEndian, tick: time.Microsecond, snaplen: 64}
	_, got, _, err := reader.readRecord()
	if err != nil {
		t.Fatalf("readRecord() error = %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %v want %v", got, payload)
	}
}
