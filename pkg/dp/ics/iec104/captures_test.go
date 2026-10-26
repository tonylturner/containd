// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package iec104

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/capture"
	"github.com/tonylturner/containd/pkg/dp/dpi"
)

const captureDir = "../../../../test/iec104/testdata"

type captureSegment struct {
	frame int
	bytes []byte
}

type captureStream struct {
	name     string
	dir      dpi.StreamDir
	segments []captureSegment
	bytes    []byte
}

type referenceCapture struct {
	name    string
	streams []*captureStream
	oracle  map[int]map[string]string
}

// Read the checked-in pcaps directly, not a second copy of their bytes. The
// manifest authenticates provenance; the independent Wireshark tables below
// authenticate the decoded fields. No libpcap, tshark or new module is needed.
func loadReferenceCaptures(tb testing.TB) []referenceCapture {
	tb.Helper()
	manifest, err := os.ReadFile(filepath.Join(captureDir, "SHA256SUMS"))
	if err != nil {
		tb.Fatal(err)
	}
	var out []referenceCapture
	for _, line := range strings.Split(strings.TrimSpace(string(manifest)), "\n") {
		cols := strings.Fields(line)
		if len(cols) != 2 || filepath.Base(cols[1]) != cols[1] || !strings.HasSuffix(cols[1], ".pcap") {
			tb.Fatalf("invalid capture manifest line %q", line)
		}
		b, err := os.ReadFile(filepath.Join(captureDir, cols[1]))
		if err != nil {
			tb.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(b)); got != cols[0] {
			tb.Fatalf("%s SHA256 %s, want %s", cols[1], got, cols[0])
		}
		ref := referenceCapture{name: cols[1], oracle: loadCaptureOracle(tb, cols[1])}
		ref.streams = readCaptureStreams(tb, ref.name, b)
		out = append(out, ref)
	}
	if len(out) != 5 {
		tb.Fatalf("expected five reference captures, got %d", len(out))
	}
	return out
}

// This deliberately supports exactly the reference capture format: classic
// little-endian pcap 2.4, Ethernet/IPv4/TCP, full records, in-order payloads.
// A changed format, gap, retransmission or tuple reuse fails loudly rather
// than silently producing a different corpus. This is not a TCP reassembler.
func readCaptureStreams(tb testing.TB, name string, b []byte) []*captureStream {
	tb.Helper()
	le := binary.LittleEndian
	if len(b) < 24 || le.Uint32(b) != 0xa1b2c3d4 ||
		le.Uint16(b[4:]) != 2 || le.Uint16(b[6:]) != 4 || le.Uint32(b[20:]) != 1 {
		tb.Fatalf("%s: expected classic Ethernet pcap 2.4", name)
	}
	snaplen := le.Uint32(b[16:])
	streams := make(map[string]*captureStream)
	nextSeq := make(map[string]uint32)
	var out []*captureStream
	for off, frame := 24, 1; off < len(b); frame++ {
		if len(b)-off < 16 {
			tb.Fatalf("%s frame %d: short record header", name, frame)
		}
		size, original := le.Uint32(b[off+8:]), le.Uint32(b[off+12:])
		off += 16
		if size != original || size > snaplen || uint64(size) > uint64(len(b)-off) || size < 14 {
			tb.Fatalf("%s frame %d: truncated record", name, frame)
		}
		eth := b[off : off+int(size)]
		off += int(size)
		if binary.BigEndian.Uint16(eth[12:]) != 0x0800 {
			tb.Fatalf("%s frame %d: expected IPv4 Ethernet", name, frame)
		}
		pkt := capture.DecodeIPPacket(eth[14:])
		if pkt.Invalid != "" || pkt.Proto != 6 || pkt.SrcPort != 2404 && pkt.DstPort != 2404 {
			tb.Fatalf("%s frame %d: invalid IEC104 TCP packet: %+v", name, frame, pkt)
		}
		key := fmt.Sprintf("%s:%d/%s:%d", pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort)
		if len(pkt.Payload) == 0 {
			if pkt.TCP.Flags&capture.TCPFlagSYN != 0 {
				if _, exists := nextSeq[key]; exists {
					tb.Fatalf("%s frame %d: reused tuple %s", name, frame, key)
				}
				nextSeq[key] = pkt.TCP.Seq + 1
			}
			continue
		}
		if seq, ok := nextSeq[key]; !ok || seq != pkt.TCP.Seq {
			tb.Fatalf("%s frame %d: non-contiguous TCP sequence in %s", name, frame, key)
		}
		nextSeq[key] += uint32(len(pkt.Payload))
		s := streams[key]
		if s == nil {
			s = &captureStream{name: name + "/" + key, dir: dpi.ClientToServer}
			if pkt.SrcPort == 2404 {
				s.dir = dpi.ServerToClient
			}
			streams[key] = s
			out = append(out, s)
		}
		s.segments = append(s.segments, captureSegment{frame: frame, bytes: pkt.Payload})
		s.bytes = append(s.bytes, pkt.Payload...)
	}
	if len(out) == 0 {
		tb.Fatalf("%s: no TCP payloads", name)
	}
	return out
}

func loadCaptureOracle(tb testing.TB, name string) map[int]map[string]string {
	tb.Helper()
	path := filepath.Join(captureDir, strings.TrimSuffix(name, ".pcap")+".expected.tsv")
	f, err := os.Open(path)
	if err != nil {
		tb.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	var header []string
	out := make(map[int]map[string]string)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cols := strings.Split(line, "\t")
		if header == nil {
			header = cols
			continue
		}
		if len(cols) != len(header) {
			tb.Fatalf("%s: expected %d columns, got %d", path, len(header), len(cols))
		}
		row := make(map[string]string, len(cols))
		for i, col := range cols {
			row[header[i]] = col
		}
		var frame int
		if _, err := fmt.Sscanf(row["frame.number"], "%d", &frame); err != nil || frame <= 0 || out[frame] != nil {
			tb.Fatalf("%s: invalid/duplicate frame %q", path, row["frame.number"])
		}
		if _, err := hex.DecodeString(row["tcp.payload"]); err != nil {
			tb.Fatalf("%s frame %d: invalid payload: %v", path, frame, err)
		}
		out[frame] = row
	}
	if err := sc.Err(); err != nil {
		tb.Fatal(err)
	}
	if len(out) == 0 {
		tb.Fatalf("%s: no oracle rows", path)
	}
	return out
}

func capturedFuzzFixtures(tb testing.TB) []fixture {
	tb.Helper()
	var out []fixture
	for _, ref := range loadReferenceCaptures(tb) {
		for _, s := range ref.streams {
			out = append(out, fixture{name: s.name, dir: s.dir, bytes: s.bytes})
			for _, seg := range s.segments {
				out = append(out, fixture{
					name: fmt.Sprintf("%s/frame-%d", ref.name, seg.frame),
					dir:  s.dir, bytes: seg.bytes,
				})
			}
		}
	}
	return out
}
