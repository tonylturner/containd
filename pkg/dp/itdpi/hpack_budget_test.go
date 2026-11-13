// SPDX-License-Identifier: Apache-2.0
package itdpi

import (
	"bytes"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/net/http2/hpack"
)

// Reflection belongs only in this version-bound audit, never in admission.
func hpackRetainedCapacity(d *hpack.Decoder) int {
	v := reflect.ValueOf(d).Elem()
	n := int(v.Type().Size())
	entries := v.FieldByName("dynTab").FieldByName("table").FieldByName("ents")
	n += entries.Cap() * int(entries.Type().Elem().Size())
	for i := 0; i < entries.Cap(); i++ {
		f := entries.Slice(0, entries.Cap()).Index(i)
		n += f.FieldByName("Name").Len() + f.FieldByName("Value").Len()
	}
	n += v.FieldByName("buf").Cap()
	n += v.FieldByName("saveBuf").FieldByName("buf").Cap()
	return n
}

func TestHPACKLifetimeEnvelope(t *testing.T) {
	version, err := exec.Command("go", "list", "-m", "-f", "{{if .Replace}}replacement={{.Replace.Path}}@{{.Replace.Version}}{{else}}{{.Version}}{{end}}", "golang.org/x/net").Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(version)) != "v0.62.0" {
		t.Fatalf("re-audit HPACK envelope for x/net %s", version)
	}
	newDecoder := func() *hpack.Decoder {
		d := hpack.NewDecoder(hpackTableSize, discardHPACKField)
		d.SetAllowedMaxDynamicTableSize(hpackTableSize)
		d.SetMaxStringLength(maxHTTPHeaders)
		return d
	}
	check := func(t *testing.T, d *hpack.Decoder) {
		t.Helper()
		// Also test the conservative old+new replacement multiplier, although
		// reflection can sample retained storage only between Write calls.
		if n := 3 * hpackRetainedCapacity(d); n > hpackDecoderEnvelopeBytes {
			t.Fatalf("capacity including replacement allowance %d exceeds envelope %d", n, hpackDecoderEnvelopeBytes)
		}
	}
	t.Run("max_size_entry_and_eviction", func(t *testing.T) {
		d := newDecoder()
		var buf bytes.Buffer
		e := hpack.NewEncoder(&buf)
		for i := 0; i < 512; i++ {
			buf.Reset()
			// RFC size = 1 + 4063 + 32 = 4096.
			value := strings.Repeat(string(rune('a'+i%26)), hpackTableSize-33)
			if err := e.WriteField(hpack.HeaderField{Name: "x", Value: value}); err != nil {
				t.Fatal(err)
			}
			if _, err := d.Write(buf.Bytes()); err != nil {
				t.Fatal(err)
			}
			if err := d.Close(); err != nil {
				t.Fatal(err)
			}
			check(t, d)
		}
		d.SetMaxDynamicTableSize(0)
		check(t, d)
	})
	t.Run("max_count_churn", func(t *testing.T) {
		d := newDecoder()
		// Empty literal fields occupy exactly 32 RFC bytes. They are invalid
		// HTTP but HPACK still indexes them before HTTP validation rejects.
		for i := 0; i < 4096; i++ {
			if _, err := d.Write([]byte{0x40, 0, 0}); err != nil {
				t.Fatal(err)
			}
			if err := d.Close(); err != nil {
				t.Fatal(err)
			}
			check(t, d)
		}
		if n := reflect.ValueOf(d).Elem().FieldByName("dynTab").FieldByName("table").FieldByName("ents").Len(); n != hpackTableSize/32 {
			t.Fatalf("did not reach maximum entry count: %d", n)
		}
		d.SetMaxDynamicTableSize(0)
		check(t, d)
	})
	t.Run("max_string_and_truncated_max_block", func(t *testing.T) {
		d := newDecoder()
		var buf bytes.Buffer
		if err := hpack.NewEncoder(&buf).WriteField(hpack.HeaderField{Name: "x", Value: strings.Repeat("z", maxHTTPHeaders)}); err != nil {
			t.Fatal(err)
		}
		if _, err := d.Write(buf.Bytes()); err != nil {
			t.Fatal(err)
		}
		if err := d.Close(); err != nil {
			t.Fatal(err)
		}
		check(t, d)
		// Non-Huffman lengths 32768 for both name and value. The single
		// maxH2Block Write truncates the value while staying within maxStrLen.
		block := []byte{0x40, 0x7f, 0x81, 0xff, 0x01}
		block = append(block, bytes.Repeat([]byte{'a'}, maxHTTPHeaders)...)
		block = append(block, 0x7f, 0x81, 0xff, 0x01)
		block = append(block, bytes.Repeat([]byte{'b'}, maxH2Block-len(block))...)
		if _, err := d.Write(block); err != nil {
			t.Fatal(err)
		}
		check(t, d)
		if err := d.Close(); err == nil {
			t.Fatal("fixture was not truncated")
		}
		check(t, d)
		if cap := reflect.ValueOf(d).Elem().FieldByName("saveBuf").FieldByName("buf").Cap(); cap < maxH2Block {
			t.Fatalf("did not exercise maximum saved block: %d", cap)
		}
	})
	t.Run("complete_max_block", func(t *testing.T) {
		d := newDecoder()
		if _, err := d.Write(bytes.Repeat([]byte{0x88}, maxH2Block)); err != nil {
			t.Fatal(err)
		}
		if err := d.Close(); err != nil {
			t.Fatal(err)
		}
		check(t, d)
	})
}
