// SPDX-License-Identifier: Apache-2.0
package capture

import "testing"

func TestRepeatSubmitsMarkExactlyOnce(t *testing.T) {
	var calls int
	comp := newCompleter(nil, nil)
	defer comp.close()
	g := newGeneration(func(id uint32, v Verdict, mark uint32) error {
		calls++
		if id != 17 || v != VerdictRepeat || mark != 0x040000ab {
			t.Errorf("submission %d %s %#x", id, v, mark)
		}
		return nil
	}, comp, nil)
	g.deliver(17, Packet{}, func(Packet) Decision { return Decision{Action: Repeat, Mark: 0x040000ab} })
	if calls != 1 || len(g.outstanding) != 0 {
		t.Fatalf("calls=%d outstanding=%d", calls, len(g.outstanding))
	}
}
