// SPDX-License-Identifier: Apache-2.0

package pcap

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

const (
	pcapMagicMicro    = 0xa1b2c3d4
	pcapMagicNano     = 0xa1b23c4d
	maxPCAPRecordSize = 16 << 20 // 16 MiB
)

// pcapReader retains the global header's byte order and timestamp resolution
// for every record, shared by offline analysis and wire replay.
type pcapReader struct {
	r       io.Reader
	order   binary.ByteOrder
	tick    time.Duration
	snaplen uint32
}

func newPCAPReader(r io.Reader) (*pcapReader, error) {
	var header [24]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	p := &pcapReader{r: r, order: binary.LittleEndian, tick: time.Microsecond}
	switch magic := binary.LittleEndian.Uint32(header[:]); magic {
	case pcapMagicMicro:
	case 0xd4c3b2a1:
		p.order = binary.BigEndian
	case pcapMagicNano:
		p.tick = time.Nanosecond
	case 0x4d3cb2a1:
		p.order, p.tick = binary.BigEndian, time.Nanosecond
	default:
		return nil, fmt.Errorf("invalid pcap magic: 0x%08x", magic)
	}
	p.snaplen = p.order.Uint32(header[16:])
	return p, nil
}

// readRecord returns io.EOF only between records. A partial header returns
// io.ErrUnexpectedEOF without a tuple or timestamp; a partial body also returns
// its capture time and available bytes, so analysis can attribute trusted
// transport headers to truncated observer coverage. Replay must reject errors.
func (p *pcapReader) readRecord() (time.Time, []byte, bool, error) {
	var rec [16]byte
	if _, err := io.ReadFull(p.r, rec[:]); err != nil {
		return time.Time{}, nil, err == io.ErrUnexpectedEOF, err
	}
	sec, sub := p.order.Uint32(rec[:]), p.order.Uint32(rec[4:])
	inclLen, origLen := p.order.Uint32(rec[8:]), p.order.Uint32(rec[12:])
	if p.snaplen > 0 && inclLen > p.snaplen {
		return time.Time{}, nil, false, fmt.Errorf("invalid captured length %d exceeds snaplen %d", inclLen, p.snaplen)
	}
	if inclLen > maxPCAPRecordSize {
		return time.Time{}, nil, false, fmt.Errorf("invalid captured length %d exceeds maximum %d", inclLen, maxPCAPRecordSize)
	}
	if inclLen > origLen {
		return time.Time{}, nil, false, fmt.Errorf("invalid captured length %d exceeds original length %d", inclLen, origLen)
	}
	ts := time.Unix(int64(sec), int64(sub)*int64(p.tick))
	data := make([]byte, inclLen)
	n, err := io.ReadFull(p.r, data)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return ts, data[:n], true, io.ErrUnexpectedEOF
	}
	return ts, data, origLen > inclLen, err
}
