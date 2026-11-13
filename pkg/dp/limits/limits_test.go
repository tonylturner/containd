// SPDX-License-Identifier: Apache-2.0

package limits

import (
	"strings"
	"testing"
)

func TestValidateBounds(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, bounds string
		set          func(*Limits, int64)
		min, max     int64
	}{
		{"maxFlows", "1024 and 262144", func(l *Limits, n int64) { l.MaxFlows = int(n) }, MinMaxFlows, MaxMaxFlows},
		{"maxTopTalkers", "64 and 262144", func(l *Limits, n int64) { l.MaxTopTalkers = int(n) }, MinMaxTopTalkers, MaxMaxTopTalkers},
		{"maxInspectionBytes", "8388608 and 1073741824", func(l *Limits, n int64) { l.MaxInspectionBytes = n }, MinMaxInspectionBytes, MaxMaxInspectionBytes},
	} {
		for _, n := range []int64{tc.min, tc.max} {
			l := Default()
			tc.set(&l, n)
			if err := l.Validate(); err != nil {
				t.Fatal(err)
			}
		}
		for _, n := range []int64{-1, 0, tc.min - 1, tc.max + 1} {
			l := Default()
			tc.set(&l, n)
			err := l.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.name) || !strings.Contains(err.Error(), tc.bounds) {
				t.Fatalf("bad validation %s=%d: %v", tc.name, n, err)
			}
		}
	}
}
