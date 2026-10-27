// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package config

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestScanSelectionDecodesStrictly(t *testing.T) {
	for _, tc := range []struct {
		name string
		av   string
		err  string // empty: decodes
	}{
		{"full selection", `{"enabled":true,"scan":{"include":[{"sourceZones":["lan"],"destZones":["wan"],"destPorts":["80","8000-8099"]}],
			"exclude":[{"sources":["10.0.0.0/8"],"destPorts":["8080"]}],"downloadMode":"stream_tail","icsZones":["ot"],"icsAssets":["plc"]}}`, ""},
		{"null scan", `{"enabled":true,"scan":null}`, ""},
		{"retired av member stays lenient", `{"enabled":true,"failOpenIcs":true,"scan":{"include":[{"destPorts":["80"]}]}}`, ""},
		{"unknown scan key", `{"scan":{"includes":[]}}`, `services.av.scan: unknown key "includes"`},
		{"duplicate scan key", `{"scan":{"icsZones":["a"],"icsZones":["b"]}}`, `duplicate key "icsZones"`},
		{"unknown include key", `{"scan":{"include":[{"destPorts":["80"],"sources":["10.0.0.0/8"]}]}}`, `include: unknown key "sources"`},
		{"unknown exclude key", `{"scan":{"exclude":[{"destPort":["80"]}]}}`, `exclude: unknown key "destPort"`},
		{"scan must be an object", `{"scan":[]}`, "expected a JSON object"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var av AVConfig
			err := json.Unmarshal([]byte(tc.av), &av)
			if tc.err == "" {
				if err != nil {
					t.Fatalf("decode: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("decode error = %v, want %q", err, tc.err)
			}
		})
	}
}

func TestScanSelectionRoundTrips(t *testing.T) {
	in := AVConfig{Enabled: true, Scan: ScanSelection{
		Include:      []ScanInclude{{SourceZones: []string{"lan"}, DestZones: []string{"wan"}, DestPorts: []string{"80"}}},
		Exclude:      []ScanExclude{{Destinations: []string{"192.0.2.0/24"}}},
		DownloadMode: ScanDownloadStreamTail, ICSZones: []string{"ot"}, ICSAssets: []string{"plc"},
	}}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out AVConfig
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round trip changed the selection:\n%+v\n%+v", in, out)
	}
}

func TestScanGateEnabled(t *testing.T) {
	include := []ScanInclude{{DestPorts: []string{"80"}}}
	for _, tc := range []struct {
		name string
		av   AVConfig
		want bool
	}{
		{"download", AVConfig{Enabled: true, HTTPDownload: true, Scan: ScanSelection{Include: include}}, true},
		{"upload", AVConfig{Enabled: true, HTTPUpload: true, Scan: ScanSelection{Include: include}}, true},
		{"scanning off", AVConfig{HTTPDownload: true, Scan: ScanSelection{Include: include}}, false},
		{"no include", AVConfig{Enabled: true, HTTPDownload: true, Scan: ScanSelection{Exclude: []ScanExclude{{DestPorts: []string{"80"}}}}}, false},
		{"no http direction", AVConfig{Enabled: true, Scan: ScanSelection{Include: include}}, false},
	} {
		if got := tc.av.ScanGateEnabled(); got != tc.want {
			t.Errorf("%s: ScanGateEnabled = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestScanDefaults(t *testing.T) {
	if got := (ScanSelection{}).EffectiveDownloadMode(); got != ScanDownloadHold {
		t.Fatalf("download mode = %q", got)
	}
	if got := (ScanSelection{DownloadMode: " Stream_Tail "}).EffectiveDownloadMode(); got != ScanDownloadStreamTail {
		t.Fatalf("download mode = %q", got)
	}
	if got := (AVConfig{}).EffectiveFailPolicy(); got != "open" {
		t.Fatalf("fail policy = %q", got)
	}
	if got := (AVConfig{FailPolicy: " Closed"}).EffectiveFailPolicy(); got != "closed" {
		t.Fatalf("fail policy = %q", got)
	}
}
