// SPDX-License-Identifier: Apache-2.0

package replay

import (
	"fmt"
	"slices"
	"sync"

	"github.com/tonylturner/containd/pkg/common/telemetry"
)

// Counters owns cumulative illustrative traffic totals and progress for one
// Run. Its zero value is ready to use. Samples are absent while stopped.
type Counters struct {
	mu      sync.Mutex
	running bool
	status  Status
	ifaces  map[string]*ifaceCount
	pairs   map[[2]string]*pairCount
}

type ifaceCount struct{ rxBytes, txBytes, rxPackets, txPackets uint64 }
type pairCount struct{ bytes, packets uint64 }

func (c *Counters) start(set *CaptureSet, topo Topology) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.running {
		return fmt.Errorf("replay counters already running")
	}
	c.status = Status{}
	c.ifaces = map[string]*ifaceCount{}
	c.pairs = map[[2]string]*pairCount{}
	for _, cap := range set.Captures {
		if len(cap.records) == 0 {
			return fmt.Errorf("%s: unverified or empty capture", cap.File)
		}
		from, to := topo.ResolveZones(cap.Family)
		if from == "" || to == "" {
			return fmt.Errorf("no non-mgmt demo zones")
		}
		c.ifaces[from], c.ifaces[to] = &ifaceCount{}, &ifaceCount{}
		if from != to {
			c.pairs[[2]string{from, to}] = &pairCount{}
			c.pairs[[2]string{to, from}] = &pairCount{}
		}
	}
	c.running = true
	return nil
}

func (c *Counters) stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.running = false
}

func (c *Counters) progress(loops uint64, file string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status = Status{Loops: loops, Capture: file}
}

func (c *Counters) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status
}

func (c *Counters) charge(from, to string, linkBytes, ipBytes uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ifaces[from].txBytes += linkBytes
	c.ifaces[from].txPackets++
	c.ifaces[to].rxBytes += linkBytes
	c.ifaces[to].rxPackets++
	if from != to {
		pair := c.pairs[[2]string{from, to}]
		pair.bytes += ipBytes
		pair.packets++
	}
}

// Samples returns owned immutable samples. runID must identify this Run and
// change when Run resets these totals, never at a capture or loop boundary.
func (c *Counters) Samples(runID string) []telemetry.CounterSample {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running {
		return nil
	}
	var out []telemetry.CounterSample
	add := func(metric telemetry.Metric, dims map[string]string, value uint64) {
		out = append(out, telemetry.CounterSample{Metric: metric, Dims: dims, Value: value, Epoch: runID, Origin: telemetry.OriginDemo})
	}
	var zones []string
	for zone := range c.ifaces {
		zones = append(zones, zone)
	}
	slices.Sort(zones)
	for _, zone := range zones {
		v := c.ifaces[zone]
		for _, counter := range []struct {
			metric telemetry.Metric
			value  uint64
		}{{telemetry.IfaceRxBytes, v.rxBytes}, {telemetry.IfaceTxBytes, v.txBytes},
			{telemetry.IfaceRxPackets, v.rxPackets}, {telemetry.IfaceTxPackets, v.txPackets}} {
			add(counter.metric, map[string]string{"interface": "demo:" + zone, "zone": zone, "role": "leaf"}, counter.value)
		}
		for _, to := range zones {
			if v := c.pairs[[2]string{zone, to}]; v != nil {
				add(telemetry.ConduitBytes, map[string]string{"from": zone, "to": to}, v.bytes)
				add(telemetry.ConduitPackets, map[string]string{"from": zone, "to": to}, v.packets)
			}
		}
	}
	return out
}
