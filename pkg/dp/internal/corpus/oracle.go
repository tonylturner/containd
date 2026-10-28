// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package corpus

import (
	"bytes"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// OracleRow preserves independent columns verbatim, including empty cells.
// Frame is one-based; PDU and Object are zero-based normalized ordinals.
// No comma-joined field is interpreted as a nested protocol object.
type OracleRow struct {
	Capture            string
	Frame, PDU, Object int
	Fields             map[string]string
}

func ReadOracle(r io.Reader, captureName string) ([]OracleRow, error) {
	b, err := io.ReadAll(io.LimitReader(r, (8<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > 8<<20 {
		return nil, fmt.Errorf("oracle exceeds bounds")
	}
	cr := csv.NewReader(bytes.NewReader(b))
	cr.Comma = '\t'
	head, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("oracle header: %w", err)
	}
	columns := map[string]bool{}
	for _, h := range head {
		if h == "" || columns[h] {
			return nil, fmt.Errorf("empty/duplicate oracle column")
		}
		columns[h] = true
	}
	if !columns["frame.number"] || (!columns["tcp.payload"] && !columns["udp.payload"]) {
		return nil, fmt.Errorf("missing oracle attribution columns")
	}
	var rows []OracleRow
	seen := map[string]bool{}
	for {
		cells, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("oracle row: %w", err)
		}
		if len(rows) >= MaxPackets {
			return nil, fmt.Errorf("oracle row bound")
		}
		row := OracleRow{Capture: captureName, Fields: map[string]string{}}
		for i, h := range head {
			row.Fields[h] = cells[i]
		}
		row.Frame, err = strconv.Atoi(row.Fields["frame.number"])
		if err != nil || row.Frame <= 0 {
			return nil, fmt.Errorf("invalid oracle frame")
		}
		for key, dst := range map[string]*int{"pdu": &row.PDU, "object": &row.Object} {
			if columns[key] {
				v, e := strconv.Atoi(row.Fields[key])
				if e != nil || v < 0 {
					return nil, fmt.Errorf("invalid %s ordinal", key)
				}
				*dst = v
			}
		}
		key := fmt.Sprintf("%d/%d/%d", row.Frame, row.PDU, row.Object)
		if seen[key] {
			return nil, fmt.Errorf("duplicate oracle identity %s", key)
		}
		seen[key] = true
		for _, col := range []string{"tcp.payload", "udp.payload"} {
			if v := row.Fields[col]; v != "" {
				if _, err := payloadHex(v); err != nil {
					return nil, fmt.Errorf("invalid %s: %w", col, err)
				}
			}
		}
		rows = append(rows, row)
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("empty oracle")
	}
	return rows, nil
}
func payloadHex(s string) ([]byte, error) { return hex.DecodeString(strings.ReplaceAll(s, ":", "")) }
func validateOracle(f Fixture) error {
	records := map[int]Packet{}
	for _, p := range f.Packets {
		records[p.Source[0].Frame] = p
	}
	expected := map[int]bool{}
	unobserved := map[int]bool{}
	for _, n := range f.Spec.OracleFrames {
		if n <= 0 || expected[n] {
			return fmt.Errorf("invalid/duplicate oracle frame declaration")
		}
		if _, ok := records[n]; !ok {
			return fmt.Errorf("oracle selects missing frame %d", n)
		}
		expected[n] = true
	}
	for _, n := range f.Spec.UnobservedFrames {
		p, ok := records[n]
		if !ok || len(p.Decoded.Payload) == 0 || unobserved[n] || expected[n] {
			return fmt.Errorf("invalid unobserved frame %d", n)
		}
		unobserved[n] = true
	}
	actual := map[int]bool{}
	for _, row := range f.Oracle {
		p, ok := records[row.Frame]
		if !ok || !expected[row.Frame] {
			return fmt.Errorf("extra oracle frame %d", row.Frame)
		}
		col := p.Decoded.Transport + ".payload"
		raw, ok := row.Fields[col]
		if !ok {
			return fmt.Errorf("missing %s column", col)
		}
		v, err := payloadHex(raw)
		if err != nil || string(v) != string(p.Decoded.Payload) {
			return fmt.Errorf("oracle payload mismatch frame %d", row.Frame)
		}
		other := "udp.payload"
		if p.Decoded.Transport == "udp" {
			other = "tcp.payload"
		}
		if row.Fields[other] != "" {
			return fmt.Errorf("oracle wrong transport payload")
		}
		actual[row.Frame] = true
	}
	for n := range expected {
		if !actual[n] {
			return fmt.Errorf("missing oracle frame %d", n)
		}
	}
	for n, p := range records {
		if len(p.Decoded.Payload) > 0 && !expected[n] && !unobserved[n] {
			return fmt.Errorf("payload frame %d lacks observation declaration", n)
		}
	}
	return nil
}
