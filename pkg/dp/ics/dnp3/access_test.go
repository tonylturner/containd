// SPDX-License-Identifier: Apache-2.0
package dnp3

import (
	"fmt"
	"slices"
	"testing"

	"github.com/tonylturner/containd/pkg/dp/dpi"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields"
	"github.com/tonylturner/containd/pkg/dp/ics/eventfields/decodertest"
)

func TestAccessEveryFunctionCode(t *testing.T) {
	for code := range 256 {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			fc := uint8(code)
			control := code >= 3 && code <= 22 || code >= 24 && code <= 33
			write := code == 2 || control
			known := write || slices.Contains([]int{0, 1, 23, 129, 130, 131}, code)
			user := []byte{0xc0, 0xc0, fc}
			if code >= 128 {
				user = append(user, 0, 0) // IIN in response-form headers.
			}
			wire := buildTestFrame(byte(5+len(user)), 0xc4, 1, 2, user)
			res, err := NewDecoder().ParseStream(nil, dpi.StreamView{Bytes: wire})
			if err != nil || len(res.Frames) != 1 || len(res.Frames[0].Events) != 1 {
				t.Fatalf("decode=%+v err=%v", res, err)
			}
			ev := res.Frames[0].Events[0]
			kind := "request"
			switch {
			case code >= 128:
				kind = "response"
			case code == 13 || code == 14:
				kind = "restart"
			case control:
				kind = "control"
			}
			if ev.Kind != kind {
				t.Fatalf("kind=%s want=%s", ev.Kind, kind)
			}
			for form, attrs := range decodertest.Forms(t, ev.Attributes) {
				gotWrite, hasWrite := eventfields.Bool(attrs, eventfields.KeyIsWrite)
				gotControl, hasControl := eventfields.Bool(attrs, "is_control")
				if hasWrite != known || hasControl != known ||
					known && (gotWrite != write || gotControl != control) {
					t.Fatalf("%s write=%v/%v control=%v/%v want known=%v write=%v control=%v",
						form, gotWrite, hasWrite, gotControl, hasControl, known, write, control)
				}
				gotFC, hasFC := eventfields.Uint8(attrs, eventfields.KeyFunctionCode)
				if !hasFC || gotFC != fc {
					t.Fatalf("%s function_code=%v/%v want=%d", form, gotFC, hasFC, fc)
				}
			}
			if IsWriteFunctionCode(fc) != write || IsControlFunctionCode(fc) != control {
				t.Fatal("public helpers disagree with decoded classification")
			}
		})
	}
}
