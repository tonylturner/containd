// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 containd Authors

package modbus

import (
	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/flow"
	"testing"
)

func TestModbusResponseKinds(t *testing.T) {
	for _, dir := range []flow.Direction{flow.DirForward, flow.DirReverse} {
		st := modbusState()
		st.Key = st.Key.Reversed()
		st.Key.Dir = dir
		for _, tc := range []struct {
			adu  []byte
			kind string
		}{
			{[]byte{0, 1, 0, 0, 0, 5, 1, 3, 2, 0, 42}, "response"},
			{writeADU, "response"},
			{[]byte{0, 1, 0, 0, 0, 3, 1, 0x83, 2}, "exception"},
		} {
			res, err := NewDecoder().ParseStream(st, dpi.StreamView{Bytes: tc.adu})
			if err != nil || len(res.Frames) != 1 {
				t.Fatalf("parse: %+v %v", res, err)
			}
			if got := res.Frames[0].Events[0].Kind; got != tc.kind {
				t.Fatalf("kind=%q want %q", got, tc.kind)
			}
		}
	}
}
