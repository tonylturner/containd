// SPDX-License-Identifier: Apache-2.0

package pcap

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/ics/modbus"
)

func formatPCAP(order binary.ByteOrder, nano bool, frames [][]byte, times []time.Time) []byte {
	var buf bytes.Buffer
	header := make([]byte, 24)
	magic := uint32(pcapMagicMicro)
	if nano {
		magic = pcapMagicNano
	}
	order.PutUint32(header, magic)
	order.PutUint16(header[4:], 2)
	order.PutUint16(header[6:], 4)
	order.PutUint32(header[16:], 65535)
	order.PutUint32(header[20:], 1)
	buf.Write(header)
	for i, frame := range frames {
		rec := make([]byte, 16)
		order.PutUint32(rec, uint32(times[i].Unix()))
		sub := times[i].Nanosecond()
		if !nano {
			sub /= 1000
		}
		order.PutUint32(rec[4:], uint32(sub))
		order.PutUint32(rec[8:], uint32(len(frame)))
		order.PutUint32(rec[12:], uint32(len(frame)))
		buf.Write(rec)
		buf.Write(frame)
	}
	return buf.Bytes()
}

func TestPCAPByteOrderAndResolution(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for _, nano := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/nano=%v", order, nano), func(t *testing.T) {
				at := time.Unix(1234567890, 123456789)
				if !nano {
					at = at.Truncate(time.Microsecond)
				}
				// Preserve backwards capture time as well as subsecond precision.
				times := []time.Time{at, at.Add(-time.Second)}
				frames := [][]byte{
					tcpEthernetFrame(1000, 0x18, modbusADU(1, 3, 0, 2)),
					tcpEthernetFrame(1012, 0x18, modbusADU(2, 6, 1, 42)),
				}
				raw := formatPCAP(order, nano, frames, times)
				reader, err := newPCAPReader(bytes.NewReader(raw))
				if err != nil {
					t.Fatal(err)
				}
				for i := range frames {
					ts, data, truncated, err := reader.readRecord()
					if err != nil || truncated || !ts.Equal(times[i]) || !bytes.Equal(data, frames[i]) {
						t.Fatalf("record %d = %v, %x, %v, %v", i, ts, data, truncated, err)
					}
				}
				if _, _, truncated, err := reader.readRecord(); err != io.EOF || truncated {
					t.Fatalf("clean EOF = %v, %v", truncated, err)
				}
				result, err := Analyze(bytes.NewReader(raw), modbus.NewDecoder())
				if err != nil {
					t.Fatal(err)
				}
				events := decodedEvents(result.Events)
				if result.Truncated || result.PacketCount != 2 || len(events) != 2 {
					t.Fatalf("analysis = %+v", result)
				}
				for i, ev := range events {
					if !ev.Timestamp.Equal(times[i]) {
						t.Fatalf("event %d timestamp = %v, want %v", i, ev.Timestamp, times[i])
					}
				}
			})
		}
	}
}

func TestPCAPPartialFinalRecordCoverage(t *testing.T) {
	frames := [][]byte{
		orientedModbusFrame(false, 49152, 1502, 99, 2, nil),
		orientedModbusFrame(false, 49152, 1502, 100, 0x18, modbusADU(1, 3, 0, 2)),
	}
	raw := buildPCAP(frames)
	second := 24 + 16 + len(frames[0])
	for _, cut := range []int{1, 15, 16, 17, 16 + 54, 16 + len(frames[1]) - 1} {
		t.Run(fmt.Sprint(cut), func(t *testing.T) {
			reader, err := newPCAPReader(bytes.NewReader(raw[:second+cut]))
			if err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := reader.readRecord(); err != nil {
				t.Fatal(err)
			}
			if _, _, truncated, err := reader.readRecord(); err != io.ErrUnexpectedEOF || !truncated {
				t.Fatalf("partial record must not look like clean EOF: %v, %v", truncated, err)
			}
			result, err := Analyze(bytes.NewReader(raw[:second+cut]), modbus.NewDecoder())
			if err != nil {
				t.Fatal(err)
			}
			if !result.Truncated || result.Protocols["modbus"] != 0 {
				t.Fatalf("partial record analysis = %+v", result)
			}
			wantPackets := 1
			if cut >= 16 {
				wantPackets++
			}
			if result.PacketCount != wantPackets {
				t.Fatalf("packet count = %d, want %d", result.PacketCount, wantPackets)
			}
			if cut >= 16+54 {
				if len(result.Identifications) != 1 || result.Identifications[0].Attributes["identification_coverage"] != "truncated" {
					t.Fatalf("trusted partial tuple coverage = %+v", result.Identifications)
				}
			}
			encoded, err := json.Marshal(result)
			if err != nil || !bytes.Contains(encoded, []byte(`"truncated":true`)) {
				t.Fatalf("missing serialized coverage: %s, %v", encoded, err)
			}
		})
	}
}

func TestPCAPCorruptLengthIsNotTruncation(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for _, n := range []uint32{65536, maxPCAPRecordSize + 1} {
			raw := formatPCAP(order, false, nil, nil)
			order.PutUint32(raw[16:], n-1)
			record := make([]byte, 16)
			order.PutUint32(record[8:], n)
			order.PutUint32(record[12:], n)
			if result, err := Analyze(bytes.NewReader(append(raw, record...))); err == nil || result != nil {
				t.Fatalf("corrupt length %d accepted: %+v, %v", n, result, err)
			}
		}
	}
	raw := buildPCAP([][]byte{buildModbusEthernetFrame(1000)})
	binary.LittleEndian.PutUint32(raw[36:], 1) // original length < captured length
	if _, err := Analyze(bytes.NewReader(raw)); err == nil {
		t.Fatal("captured length exceeding original length was accepted")
	}
}
