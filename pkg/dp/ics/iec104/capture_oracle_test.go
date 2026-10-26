// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package iec104

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
)

// Project decoded events back onto the independently generated Wireshark
// columns. Header columns occur once per APDU, object columns once per object.
// Invalid DCS and unsupported Type 104 intentionally have no decoded objects;
// their header fields are still checked, and their kinds are asserted below.
func checkCaptureOracle(t *testing.T, res dpi.StreamResult, row map[string]string, badObjects bool) {
	t.Helper()
	got := make(map[string][]string)
	add := func(col string, value any) { got[col] = append(got[col], fmt.Sprint(value)) }
	for _, frame := range res.Frames {
		a := frame.Events[0].Attributes
		format := a[eventfields.KeyAPCIType].(string)
		add("iec60870_104.apdulen", frame.End-frame.Start-2)
		add("iec60870_104.type", map[string]int{"I": 0, "S": 1, "U": 3}[format])
		if format == "U" {
			add("iec60870_104.utype", map[string]int{
				"startdt_act": 1, "startdt_con": 2, "stopdt_act": 4,
				"stopdt_con": 8, "testfr_act": 16, "testfr_con": 32,
			}[fmt.Sprint(a[eventfields.KeyUFunction])])
			continue
		}
		add("iec60870_104.rx", a[eventfields.KeyReceiveSequence])
		if format == "S" {
			continue
		}
		add("iec60870_104.tx", a[eventfields.KeySendSequence])
		for col, key := range map[string]string{
			"typeid": eventfields.KeyTypeID, "sq": eventfields.KeySQ,
			"numix": eventfields.KeyObjectCount, "causetx": eventfields.KeyCause,
			"nega": eventfields.KeyCOTNegative, "test": eventfields.KeyCOTTest,
			"oa": eventfields.KeyOriginator, "addr": eventfields.KeyCA,
		} {
			add("iec60870_asdu."+col, a[key])
		}
		if badObjects {
			continue
		}
		for _, ev := range frame.Events {
			a := ev.Attributes
			add("iec60870_asdu.ioa", a[eventfields.KeyIOA])
			switch a[eventfields.KeyTypeID] {
			case uint8(3), uint8(31):
				add("iec60870_asdu.diq", a[eventfields.KeyValue].(uint8)|a[eventfields.KeyQuality].(uint8))
			case uint8(13):
				add("iec60870_asdu.float", a[eventfields.KeyValue])
				add("iec60870_asdu.qds", a[eventfields.KeyQuality])
			case uint8(46):
				dco := a[eventfields.KeyValue].(uint8) | a[eventfields.KeyQualifier].(uint8)<<2
				if a[eventfields.KeySelect] == true {
					dco |= 0x80
				}
				add("iec60870_asdu.dco", dco)
				add("iec60870_asdu.dco.se", a[eventfields.KeySelect])
			case uint8(100):
				add("iec60870_asdu.qoi", a[eventfields.KeyQualifier])
			}
			if ts, ok := a[eventfields.KeySourceTime]; ok {
				add("iec60870_asdu.cp56time", ts)
			}
		}
	}
	columns := []string{
		"iec60870_104.apdulen", "iec60870_104.type", "iec60870_104.utype",
		"iec60870_104.tx", "iec60870_104.rx",
		"iec60870_asdu.typeid", "iec60870_asdu.sq", "iec60870_asdu.numix",
		"iec60870_asdu.causetx", "iec60870_asdu.nega", "iec60870_asdu.test",
		"iec60870_asdu.oa", "iec60870_asdu.addr",
	}
	if !badObjects {
		columns = append(columns, "iec60870_asdu.ioa", "iec60870_asdu.diq",
			"iec60870_asdu.float", "iec60870_asdu.qds", "iec60870_asdu.dco",
			"iec60870_asdu.dco.se", "iec60870_asdu.qoi", "iec60870_asdu.cp56time")
	}
	for _, col := range columns {
		want := []string(nil)
		if row[col] != "" {
			want = strings.Split(row[col], ",")
		}
		if len(got[col]) != len(want) {
			t.Fatalf("%s: got %v, want %v", col, got[col], want)
		}
		for i, actual := range got[col] {
			expected := want[i]
			if col == "iec60870_asdu.cp56time" {
				// CP56Time2a has no timezone. Wireshark attached the capture
				// host's zone; compare wall-clock fields, not instants.
				ts, err := time.Parse("2006-01-02T15:04:05.999999999-0700", expected)
				if err != nil || ts.Format("2006-01-02T15:04:05.000") != actual {
					t.Fatalf("%s: got %s, want wall time of %s", col, actual, expected)
				}
				continue
			}
			if strings.EqualFold(actual, expected) {
				continue
			}
			parse := func(s string) (float64, error) {
				if strings.HasPrefix(s, "0x") {
					v, err := strconv.ParseUint(s[2:], 16, 64)
					return float64(v), err
				}
				return strconv.ParseFloat(s, 64)
			}
			a, ae := parse(actual)
			b, be := parse(expected)
			tolerance := 0.0
			if col == "iec60870_asdu.float" {
				tolerance = 1e-6 * math.Max(1, math.Abs(b)) // TSV rounds float32s.
			}
			if ae != nil || be != nil || math.Abs(a-b) > tolerance {
				t.Fatalf("%s[%d]: got %s, want %s", col, i, actual, expected)
			}
		}
	}
}
