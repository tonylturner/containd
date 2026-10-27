// SPDX-License-Identifier: Apache-2.0
//go:build linux

package enforce

import (
	"net/netip"
	"testing"
	"time"

	"github.com/tonylturner/containd/pkg/dp/rules"
)

// TestKernelEngineAPIReachableOnlyOnItsPath serves the engine API port on
// every address of the router and enforces a deny-all policy. The target
// namespace stands for the network management uses to reach a split-mode
// engine, the client namespace for any other zone. Loopback always reaches
// the API. With the listener bound to the router's target-side address, the
// target network reaches it there; the client reaches it at neither router
// address, not even by routing to the target-side one. With a loopback or
// wildcard listener, neither network reaches it.
func TestKernelEngineAPIReachableOnlyOnItsPath(t *testing.T) {
	lab := newNetnsLab(t, "api", 110, 30*time.Second)
	const port = 8081
	lab.run(t, "ip", "-n", lab.client, "route", "add", "198.18.120.0/24", "via", "198.18.110.1")
	lab.serveLocal(t, "0.0.0.0", port)
	snap := &rules.Snapshot{
		Default:    rules.ActionDeny,
		ZoneIfaces: map[string][]string{"lan": {"api0"}, "mgmt": {"api1"}},
	}
	path := &EngineAPIPath{Device: "api1", Addr: netip.MustParseAddr("198.18.120.1"), Port: port}
	for _, tc := range []struct {
		name string
		path *EngineAPIPath
	}{{"bound", path}, {"loopback or wildcard", nil}} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewCompiler()
			c.EngineAPI = tc.path
			lab.apply(t, c, snap)
			if err := lab.probeFrom("", "127.0.0.1", port, "127.0.0.1"); err != nil {
				t.Fatalf("loopback cannot reach the engine API: %v", err)
			}
			err := lab.probeFrom(lab.target, "198.18.120.1", port, "198.18.120.2")
			if tc.path != nil && err != nil {
				t.Fatalf("management network cannot reach the engine API: %v", err)
			}
			if tc.path == nil && err == nil {
				t.Fatal("management network reached an engine API with no path")
			}
			for _, addr := range []string{"198.18.110.1", "198.18.120.1"} {
				if err := lab.probe(addr, port, "198.18.110.2"); err == nil {
					t.Fatalf("another zone reached the engine API at %s", addr)
				}
			}
		})
	}
}
