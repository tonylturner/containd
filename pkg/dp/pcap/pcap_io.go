package pcap

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

const (
	pcapMagic        = 0xa1b2c3d4
	pcapVersionMajor = 2
	pcapVersionMinor = 4
)

func writePCAPGlobalHeader(w io.Writer, snaplen uint32) error {
	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header[0:], pcapMagic)
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

func readPCAPGlobalHeader(r io.Reader) (uint32, error) {
	header := make([]byte, 24)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, err
	}
	magic := binary.LittleEndian.Uint32(header[0:])
	if magic != pcapMagic {
		return 0, fmt.Errorf("invalid pcap magic")
	}
	snaplen := binary.LittleEndian.Uint32(header[16:])
	return snaplen, nil
}

func readPCAPPacket(r io.Reader) (time.Time, []byte, error) {
	rec := make([]byte, 16)
	if _, err := io.ReadFull(r, rec); err != nil {
		return time.Time{}, nil, err
	}
	sec := binary.LittleEndian.Uint32(rec[0:])
	usec := binary.LittleEndian.Uint32(rec[4:])
	origLen := binary.LittleEndian.Uint32(rec[8:])
	if origLen == 0 {
		return time.Unix(int64(sec), int64(usec)*1000), nil, nil
	}
	data := make([]byte, origLen)
	if _, err := io.ReadFull(r, data); err != nil {
		return time.Time{}, nil, err
	}
	ts := time.Unix(int64(sec), int64(usec)*1000)
	return ts, data, nil
}
