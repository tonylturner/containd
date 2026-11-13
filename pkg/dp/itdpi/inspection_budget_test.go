// SPDX-License-Identifier: Apache-2.0
package itdpi

import (
	"errors"
	"testing"
	"unsafe"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/limits"
)

func requireInspectionLimit(t *testing.T, err error) {
	t.Helper()
	var se *dpi.StreamError
	if !errors.As(err, &se) || se.Kind != dpi.StreamStateLimit {
		t.Fatalf("expected state_limit, got %v", err)
	}
}

func TestITInspectionMetadataAdmission(t *testing.T) {
	for _, enforcing := range []bool{false, true} {
		for _, protocol := range []string{"http", "tls"} {
			t.Run(protocol+map[bool]string{false: "/monitor", true: "/enforce"}[enforcing], func(t *testing.T) {
				r := limits.NewResources(limits.NewBudget(1), nil)
				v := dpi.StreamView{Session: "s", Bytes: []byte("GET / HTTP/1.1\r\n\r\n"), Enforcing: enforcing}
				if protocol == "http" {
					d := NewHTTPDecoder()
					d.SetResources(r)
					_, err := d.ParseStream(httpFlowState(1, 80), v)
					requireInspectionLimit(t, err)
					if len(d.streams) != 0 || len(d.connections) != 0 {
						t.Fatal("refused HTTP admission created state")
					}
				} else {
					d := NewTLSDecoder()
					d.SetResources(r)
					_, err := d.ParseStream(tlsFlowState(1, 443), v)
					requireInspectionLimit(t, err)
					if len(d.streams) != 0 || len(d.connections) != 0 {
						t.Fatal("refused TLS admission created state")
					}
				}
				if r.Budget.Status().InUse != 0 {
					t.Fatal("admission rollback leaked")
				}
				hits := r.Ledger.Status(limits.TableInspection, limits.Occupancy{}).Hits
				want := limits.ModeMonitor
				if enforcing {
					want = limits.ModeEnforce
				}
				if len(hits) != 1 || hits[0].Mode != want || hits[0].Total != 1 {
					t.Fatal(hits)
				}
			})
		}
	}
}

func TestHTTPInspectionGrowthRefusalIsTerminal(t *testing.T) {
	for _, path := range []string{"request", "request_array", "hpack", "block"} {
		t.Run(path, func(t *testing.T) {
			r := limits.NewResources(limits.NewBudget(2<<20), nil)
			d := NewHTTPDecoder()
			d.SetResources(r)
			st := httpFlowState(1, 80)
			v := dpi.StreamView{Session: "s", Enforcing: true}
			if _, err := d.ParseStream(st, v); err != nil {
				t.Fatal(err)
			}
			if path == "block" {
				v.Bytes = append([]byte(h2Preface), h2Settings()...)
				v.Bytes = append(v.Bytes, h2Frame(1, 0, 1, []byte{0x88})...)
				if _, err := d.ParseStream(st, v); err != nil {
					t.Fatal(err)
				}
			}
			if path == "request_array" {
				v.Bytes = []byte("GET / HTTP/1.1\r\n\r\n")
				if _, err := d.ParseStream(st, v); err != nil {
					t.Fatal(err)
				}
			}
			used := r.Budget.Status().InUse
			room := int64(0)
			if path == "block" {
				room = 1 // replacement is two bytes, not the one-byte delta
			} else if path == "request_array" {
				room = limits.PairingMetadataBytes + 3 + 2*int64(unsafe.Sizeof(httpRequest{})) - 1
			}
			blocker, ok := r.Budget.Reserve(limits.ClassEnforce, limits.CategoryHeld, (2<<20)-used-room)
			if !ok {
				t.Fatal("blocker")
			}
			switch path {
			case "request", "request_array":
				v.Bytes = []byte("GET / HTTP/1.1\r\n\r\n")
			case "hpack":
				v.Bytes = []byte(h2Preface)
			case "block":
				v.Bytes = h2Frame(9, 0, 1, []byte{0x88})
			}
			result, err := d.ParseStream(st, v)
			requireInspectionLimit(t, err)
			if len(result.Frames) != 0 {
				t.Fatal("published result after allocation refusal")
			}
			blocker.Release()
			_, err = d.ParseStream(st, v)
			requireInspectionLimit(t, err)
			hits := r.Ledger.Status(limits.TableInspection, limits.Occupancy{}).Hits
			if len(hits) != 1 || hits[0].Total != 1 {
				t.Fatal(hits)
			}
			d.StreamEnded("s", dpi.DirUnknown)
			d.StreamEnded("s", dpi.DirUnknown)
			if r.Budget.Status().InUse != 0 {
				t.Fatal("HTTP teardown leaked")
			}
		})
	}
}

func TestHTTPInspectionSharedRequestOwnership(t *testing.T) {
	r := limits.NewResources(limits.NewBudget(16384), nil)
	d := NewHTTPDecoder()
	d.SetResources(r)
	st := httpFlowState(1, 80)
	client := dpi.StreamView{Session: "s", Dir: dpi.ClientToServer, Bytes: []byte("HEAD / HTTP/1.1\r\n\r\n")}
	server := dpi.StreamView{Session: "s", Dir: dpi.ServerToClient, Enforcing: true}
	if _, err := d.ParseStream(st, client); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ParseStream(st, server); err != nil {
		t.Fatal(err)
	}
	var peer *httpConnection
	for _, c := range d.connections {
		peer = c
	}
	requestCredit := r.Budget.Status().InUse
	d.StreamEnded("s", dpi.ClientToServer)
	if len(peer.methods) != 1 || peer.methods[0].method != "HEAD" || r.Budget.Status().InUse >= requestCredit {
		t.Fatal("request ownership was lost with its directional stream")
	}
	server.Bytes = []byte("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
	if _, err := d.ParseStream(st, server); err != nil {
		t.Fatal(err)
	}
	if len(peer.methods) != 0 || peer.arrayMemory != nil {
		t.Fatal("response retained request backing")
	}
	d.StreamEnded("s", dpi.ServerToClient)
	if r.Budget.Status().InUse != 0 {
		t.Fatal("shared owner teardown leaked")
	}
}

func TestTLSInspectionReplacementPeak(t *testing.T) {
	r := limits.NewResources(limits.NewBudget(16384), nil)
	d := NewTLSDecoder()
	d.SetResources(r)
	st := tlsFlowState(1, 443)
	v := dpi.StreamView{Session: "s", Enforcing: true, Bytes: tlsRecord([]byte{1, 0, 0, 16, 1, 2, 3, 4})}
	if _, err := d.ParseStream(st, v); err != nil {
		t.Fatal(err)
	}
	used := r.Budget.Status().InUse
	blocker, ok := r.Budget.Reserve(limits.ClassEnforce, limits.CategoryHeld, 16384-used-7)
	if !ok {
		t.Fatal("blocker")
	}
	v.Bytes = tlsRecord([]byte{5, 6, 7, 8})
	result, err := d.ParseStream(st, v)
	requireInspectionLimit(t, err)
	if len(result.Frames) != 0 {
		t.Fatal("published refused hello")
	}
	blocker.Release()
	_, err = d.ParseStream(st, v)
	requireInspectionLimit(t, err)
	d.StreamEnded("s", dpi.DirUnknown)
	if r.Budget.Status().InUse != 0 {
		t.Fatal("TLS teardown leaked")
	}
}
