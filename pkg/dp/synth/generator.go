// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

// Package synth generates synthetic DPI events for lab/demo mode.
// When the engine runs with dpiMock=true and no capture interfaces produce
// real traffic, this generator produces a realistic mix of ICS and IT
// protocol events so the dashboard and telemetry pages have data to display.
package synth

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"time"

	dpevents "github.com/tonylturner/containd/pkg/dp/events"
)

// Subnet defines a zone-to-prefix mapping for synthetic traffic generation.
type Subnet struct {
	Zone   string // zone name (must match config zone names)
	Prefix string // IPv4 prefix, e.g. "10.10.10." — host octets are randomised
}

// Config controls the synthetic traffic generator.
type Config struct {
	// EventsPerSecond is the average rate of events to generate.
	EventsPerSecond float64
	// Subnets maps zones to address prefixes for IP generation.
	// If empty, DefaultSubnets() is used as a fallback.
	Subnets []Subnet
	// OnEvent is an optional callback invoked for each generated event.
	// The engine uses this to run IDS rule evaluation on synthetic events.
	OnEvent func(dpevents.Event)
}

// DefaultSubnets returns the built-in zone/prefix mappings.
func DefaultSubnets() []Subnet {
	return []Subnet{
		{Zone: "wan", Prefix: "203.0.113."},
		{Zone: "dmz", Prefix: "10.10.10."},
		{Zone: "lan", Prefix: "172.16.0."},
		{Zone: "mgmt", Prefix: "10.20.0."},
	}
}

// SubnetsFromInterfaces builds Subnet entries from configured interfaces.
// Each interface with a zone and at least one IPv4 address generates one Subnet
// whose prefix is derived from the first three octets of the network address.
// Zones that have no CIDR address fall back to a synthetic 10.x.x. prefix.
func SubnetsFromInterfaces(ifaces []IfaceSummary) []Subnet {
	seen := map[string]bool{}
	out := []Subnet{}
	fallback := byte(1)
	for _, ifc := range ifaces {
		if ifc.Zone == "" || seen[ifc.Zone] {
			continue
		}
		seen[ifc.Zone] = true
		prefix := prefixFromCIDR(ifc.Address)
		if prefix == "" {
			prefix = fmt.Sprintf("10.%d.%d.", fallback, fallback)
			fallback++
		}
		out = append(out, Subnet{Zone: ifc.Zone, Prefix: prefix})
	}
	if len(out) == 0 {
		return DefaultSubnets()
	}
	return out
}

// IfaceSummary is the minimal interface info needed to build subnets.
type IfaceSummary struct {
	Zone    string // zone this interface belongs to
	Address string // first IPv4 CIDR, e.g. "10.10.10.1/24" (may be empty)
}

// prefixFromCIDR extracts the first three octets of the network address.
// e.g. "192.168.100.1/24" → "192.168.100."
func prefixFromCIDR(cidr string) string {
	if cidr == "" {
		return ""
	}
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		ip = net.ParseIP(cidr)
	}
	if ip == nil {
		return ""
	}
	ip = ip.To4()
	if ip == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.", ip[0], ip[1], ip[2])
}

// DefaultConfig returns a reasonable lab demo configuration.
func DefaultConfig() Config {
	return Config{
		EventsPerSecond: 4,
		Subnets:         DefaultSubnets(),
	}
}

// Run starts the synthetic event generator. It blocks until ctx is cancelled.
func Run(ctx context.Context, store *dpevents.Store, cfg Config) {
	if store == nil {
		return
	}
	if cfg.EventsPerSecond <= 0 {
		cfg.EventsPerSecond = 4
	}
	subs := cfg.Subnets
	if len(subs) == 0 {
		subs = DefaultSubnets()
	}

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	interval := time.Duration(float64(time.Second) / cfg.EventsPerSecond)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	gen := &generator{rng: rng, cfg: cfg, subnets: subs, flowSeq: 1}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ev := gen.next()
			store.Append(ev)
			if cfg.OnEvent != nil {
				cfg.OnEvent(ev)
			}
		}
	}
}

type generator struct {
	rng     *rand.Rand
	cfg     Config
	subnets []Subnet
	flowSeq int
}

// ── Protocol scenario definitions ───────────────────────────────────

type scenario struct {
	proto     string
	kind      string
	transport string
	dstPort   uint16
	weight    int // relative probability
	attrFn    func(rng *rand.Rand) map[string]any
}

var scenarios = []scenario{
	// ICS protocols
	{proto: "modbus", kind: "allow", transport: "tcp", dstPort: 502, weight: 25, attrFn: func(rng *rand.Rand) map[string]any {
		fcs := []int{1, 2, 3, 4, 5, 6, 15, 16}
		return map[string]any{"functionCode": fcs[rng.Intn(len(fcs))], "unitId": rng.Intn(10) + 1, "registers": rng.Intn(50) + 1}
	}},
	{proto: "modbus", kind: "alert", transport: "tcp", dstPort: 502, weight: 2, attrFn: func(rng *rand.Rand) map[string]any {
		return map[string]any{"functionCode": 8, "unitId": rng.Intn(10) + 1, "message": "Modbus diagnostic command detected"}
	}},
	{proto: "dnp3", kind: "allow", transport: "tcp", dstPort: 20000, weight: 15, attrFn: func(rng *rand.Rand) map[string]any {
		fcs := []string{"READ", "WRITE", "DIRECT_OPERATE", "SELECT", "OPERATE"}
		return map[string]any{"function": fcs[rng.Intn(len(fcs))], "src": rng.Intn(50), "dst": rng.Intn(50)}
	}},
	{proto: "enip", kind: "allow", transport: "tcp", dstPort: 44818, weight: 12, attrFn: func(rng *rand.Rand) map[string]any {
		cmds := []string{"ListIdentity", "RegisterSession", "SendRRData", "SendUnitData"}
		return map[string]any{"command": cmds[rng.Intn(len(cmds))]}
	}},
	{proto: "s7comm", kind: "allow", transport: "tcp", dstPort: 102, weight: 8, attrFn: func(rng *rand.Rand) map[string]any {
		fns := []string{"ReadVar", "WriteVar", "SetupComm", "CPU.Start", "CPU.Stop"}
		return map[string]any{"function": fns[rng.Intn(len(fns))], "rack": 0, "slot": rng.Intn(4) + 1}
	}},
	{proto: "bacnet", kind: "allow", transport: "udp", dstPort: 47808, weight: 6, attrFn: func(rng *rand.Rand) map[string]any {
		svcs := []string{"ReadProperty", "WriteProperty", "WhoIs", "IAm", "COVNotification"}
		return map[string]any{"service": svcs[rng.Intn(len(svcs))], "objectId": rng.Intn(200)}
	}},
	{proto: "opcua", kind: "allow", transport: "tcp", dstPort: 4840, weight: 5, attrFn: func(rng *rand.Rand) map[string]any {
		msgs := []string{"Browse", "Read", "Write", "CreateSubscription", "Publish"}
		return map[string]any{"messageType": msgs[rng.Intn(len(msgs))], "nodeCount": rng.Intn(20) + 1}
	}},

	// IT protocols
	{proto: "dns", kind: "allow", transport: "udp", dstPort: 53, weight: 20, attrFn: func(rng *rand.Rand) map[string]any {
		domains := []string{"scada.local", "plc-01.ot.local", "historian.corp.local", "ntp.pool.org", "updates.vendor.com", "api.cloud.example.com"}
		types := []string{"A", "AAAA", "PTR", "CNAME"}
		return map[string]any{"query": domains[rng.Intn(len(domains))], "type": types[rng.Intn(len(types))]}
	}},
	{proto: "tls", kind: "allow", transport: "tcp", dstPort: 443, weight: 15, attrFn: func(rng *rand.Rand) map[string]any {
		snis := []string{"historian.corp.local", "updates.vendor.com", "cloud.scada.io", "portal.ot.local"}
		return map[string]any{"sni": snis[rng.Intn(len(snis))], "version": "TLS 1.3"}
	}},
	{proto: "http", kind: "allow", transport: "tcp", dstPort: 80, weight: 8, attrFn: func(rng *rand.Rand) map[string]any {
		paths := []string{"/api/v1/status", "/metrics", "/health", "/api/v1/data"}
		methods := []string{"GET", "POST", "GET", "GET"}
		i := rng.Intn(len(paths))
		return map[string]any{"method": methods[i], "path": paths[i], "status": 200}
	}},
	{proto: "ssh", kind: "allow", transport: "tcp", dstPort: 22, weight: 4, attrFn: func(rng *rand.Rand) map[string]any {
		return map[string]any{"cipher": "aes256-gcm", "auth": "publickey"}
	}},
	{proto: "ntp", kind: "allow", transport: "udp", dstPort: 123, weight: 5, attrFn: func(rng *rand.Rand) map[string]any {
		return map[string]any{"stratum": rng.Intn(4) + 1, "mode": "client"}
	}},
	{proto: "snmp", kind: "allow", transport: "udp", dstPort: 161, weight: 3, attrFn: func(rng *rand.Rand) map[string]any {
		ops := []string{"GetRequest", "GetNextRequest", "GetBulkRequest", "SetRequest"}
		return map[string]any{"pduType": ops[rng.Intn(len(ops))], "version": "v2c"}
	}},

	// IDS alerts (low probability) — kind "alert" matches dashboard counter (Proto=="ids" && Kind=="alert")
	{proto: "ids", kind: "alert", transport: "tcp", dstPort: 502, weight: 2, attrFn: func(rng *rand.Rand) map[string]any {
		msgs := []string{
			"Unauthorized Modbus write to coil range",
			"Modbus exception response: illegal function",
			"Unusual Modbus polling frequency detected",
		}
		sevs := []string{"medium", "high", "low"}
		i := rng.Intn(len(msgs))
		return map[string]any{"message": msgs[i], "severity": sevs[i], "ruleId": fmt.Sprintf("ICS-%04d", rng.Intn(100)+1)}
	}},
	{proto: "ids", kind: "alert", transport: "tcp", dstPort: 443, weight: 1, attrFn: func(rng *rand.Rand) map[string]any {
		msgs := []string{
			"TLS certificate mismatch for known OT host",
			"Possible C2 beacon pattern detected",
		}
		return map[string]any{"message": msgs[rng.Intn(len(msgs))], "severity": "high"}
	}},

	// AV events (rare) — kinds match dashboard counters
	{proto: "av", kind: "service.av.detected", transport: "tcp", dstPort: 445, weight: 1, attrFn: func(rng *rand.Rand) map[string]any {
		threats := []string{"Win32.Industroyer.B", "Triton.ICS", "Stuxnet.variant"}
		return map[string]any{"threat": threats[rng.Intn(len(threats))], "action": "quarantine"}
	}},

	// Block events (rare)
	{proto: "firewall", kind: "block", transport: "tcp", dstPort: 23, weight: 2, attrFn: func(rng *rand.Rand) map[string]any {
		return map[string]any{"message": "Telnet blocked by policy", "rule": "default-deny"}
	}},
}

func (g *generator) next() dpevents.Event {
	// Weighted random scenario selection
	totalWeight := 0
	for _, s := range scenarios {
		totalWeight += s.weight
	}
	roll := g.rng.Intn(totalWeight)
	var sc scenario
	for _, s := range scenarios {
		roll -= s.weight
		if roll < 0 {
			sc = s
			break
		}
	}

	// Pick source/dest from configured subnets
	subs := g.subnets
	srcNet := subs[g.rng.Intn(len(subs))]
	dstNet := subs[g.rng.Intn(len(subs))]
	// Avoid same subnet for cross-zone traffic
	for dstNet.Zone == srcNet.Zone && len(subs) > 1 {
		dstNet = subs[g.rng.Intn(len(subs))]
	}

	srcIP := fmt.Sprintf("%s%d", srcNet.Prefix, g.rng.Intn(50)+10)
	dstIP := fmt.Sprintf("%s%d", dstNet.Prefix, g.rng.Intn(50)+10)
	srcPort := uint16(g.rng.Intn(64511) + 1024)

	flowID := fmt.Sprintf("%s|%s|%d|%d|%s", srcIP, dstIP, srcPort, sc.dstPort, sc.transport)

	attrs := sc.attrFn(g.rng)
	attrs["srcZone"] = srcNet.Zone
	attrs["dstZone"] = dstNet.Zone

	g.flowSeq++

	return dpevents.Event{
		FlowID:    flowID,
		Proto:     sc.proto,
		Kind:      sc.kind,
		Attributes: attrs,
		Timestamp: time.Now().UTC(),
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   srcPort,
		DstPort:   sc.dstPort,
		Transport: sc.transport,
	}
}
