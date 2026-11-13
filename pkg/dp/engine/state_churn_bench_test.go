// SPDX-License-Identifier: Apache-2.0
package engine

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/limits"
)

// BenchmarkStateChurn keeps one bounded engine live across repeated expiry
// waves. HeapAlloc includes the runtime and other packages, not just inspection
// leases; compare the post-GC plateau on the same host and Go toolchain.
func BenchmarkStateChurn(b *testing.B) {
	const slots = 32
	for _, multiple := range []int{2, 10, 100} {
		b.Run(fmt.Sprintf("offered_%dx", multiple), func(b *testing.B) {
			c := &stateBudgetClock{}
			c.nanos.Store(time.Now().UnixNano())
			e := stateBudgetEngine(b, limits.Limits{MaxFlows: slots, MaxTopTalkers: 8, MaxInspectionBytes: 262144}, nil, c)
			b.ReportAllocs()
			b.ResetTimer()
			for wave := 0; wave < b.N; wave++ {
				c.advance(6 * time.Minute)
				for id := range slots * multiple {
					for _, p := range stateBudgetTrace(id, id%2 == 1, c.now()) {
						e.HandlePacket(p)
					}
				}
			}
			b.StopTimer()
			assertStateBudgetCaps(b, e)
			runtime.GC()
			var mem runtime.MemStats
			runtime.ReadMemStats(&mem)
			b.ReportMetric(float64(mem.HeapAlloc), "postGC-heap-B")
			runtime.KeepAlive(e) // Measure the populated engine, not its teardown.
			e.Close()
			assertStateBudgetEmpty(b, e.budget)
		})
	}
}
