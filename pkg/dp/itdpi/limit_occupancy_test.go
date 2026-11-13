// SPDX-License-Identifier: Apache-2.0

package itdpi

import "testing"

func TestHTTPCorrelationLimitOccupancy(t *testing.T) {
	d := NewHTTPDecoder()
	if o := d.LimitOccupancy(); o.Limit != 0 || o.Entries != 0 {
		t.Fatalf("empty occupancy %+v", o)
	}
	d.connections = map[string]*httpConnection{"one": {methods: make([]httpRequest, 64)}, "two": {methods: make([]httpRequest, 2)}}
	if o := d.connections["one"].LimitOccupancy(); o.Limit != 64 || o.Entries != 64 {
		t.Fatalf("FIFO %+v", o)
	}
	if o := d.LimitOccupancy(); o.Limit != 0 || o.Entries != 66 || o.ChargedBytes != 0 {
		t.Fatalf("occupancy %+v", o)
	}
}
