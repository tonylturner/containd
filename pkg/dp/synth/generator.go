// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 containd Authors

// Package synth generates synthetic DPI events for lab/demo mode.
// When the engine runs with dpiMock=true and no capture interfaces produce
// real traffic, this generator produces a realistic mix of ICS and IT
// protocol events so the dashboard and telemetry pages have data to display.
//
// Synthetic events use the same attribute keys as the real DPI decoders so
// the IDS evaluator can match rules against them and generate real alerts.
package synth

import (
	"context"
	"encoding/hex"
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
//
// All scenarios produce real DPI-level events using the same attribute keys
// as the actual decoders in pkg/dp/ics/ and pkg/dp/itdpi/. The IDS evaluator
// (OnEvent callback) matches these against configured rules and generates
// genuine alerts — no fake IDS events are injected here.

type scenario struct {
	proto     string
	kind      string
	transport string
	dstPort   uint16
	weight    int // relative probability
	attrFn    func(rng *rand.Rand) map[string]any
}

var scenarios = []scenario{
	// ── ICS protocols ─────────────────────────────────────────────
	// Modbus/TCP — attribute keys match pkg/dp/ics/modbus/decoder.go
	{proto: "modbus", kind: "request", transport: "tcp", dstPort: 502, weight: 25, attrFn: synthModbusRequest},
	{proto: "modbus", kind: "exception", transport: "tcp", dstPort: 502, weight: 3, attrFn: synthModbusException},

	// DNP3 — attribute keys match pkg/dp/ics/dnp3/decoder.go
	{proto: "dnp3", kind: "request", transport: "tcp", dstPort: 20000, weight: 15, attrFn: func(rng *rand.Rand) map[string]any {
		fcs := []int{1, 2, 3, 4, 5, 13, 14}
		fcNames := map[int]string{1: "READ", 2: "WRITE", 3: "SELECT", 4: "OPERATE", 5: "DIRECT_OPERATE", 13: "COLD_RESTART", 14: "WARM_RESTART"}
		fc := fcs[rng.Intn(len(fcs))]
		attrs := map[string]any{
			"function_code": fc,
			"function_name": fcNames[fc],
			"is_write":      fc == 2 || fc == 4 || fc == 5 || fc == 13 || fc == 14,
			"src_address":   rng.Intn(50),
			"dst_address":   rng.Intn(50),
		}
		if rng.Intn(3) == 0 {
			attrs["object_groups"] = fmt.Sprintf("G%d", rng.Intn(40)+1)
			attrs["object_count"] = rng.Intn(20) + 1
		}
		return attrs
	}},

	// CIP/EtherNet/IP — attribute keys match pkg/dp/ics/cip/decoder.go
	{proto: "enip", kind: "request", transport: "tcp", dstPort: 44818, weight: 12, attrFn: func(rng *rand.Rand) map[string]any {
		type cipSvc struct {
			code uint8
			name string
			w, c bool
		}
		svcs := []cipSvc{
			{0x4C, "Read_Tag", false, false}, {0x4D, "Write_Tag", true, false},
			{0x0E, "Get_Attribute_Single", false, false}, {0x10, "Set_Attribute_Single", true, false},
			{0x52, "Unconnected_Send", false, true},
		}
		s := svcs[rng.Intn(len(svcs))]
		return map[string]any{
			"service_code": s.code, "service_name": s.name,
			"function_code": s.code, "is_write": s.w, "is_control": s.c,
			"command": "SendRRData", "command_code": uint16(0x6F),
		}
	}},

	// S7comm — attribute keys match pkg/dp/ics/s7comm/decoder.go
	{proto: "s7comm", kind: "request", transport: "tcp", dstPort: 102, weight: 8, attrFn: func(rng *rand.Rand) map[string]any {
		type s7fn struct {
			fc   uint8
			name string
			w, c bool
		}
		fns := []s7fn{
			{4, "Read Var", false, false}, {5, "Write Var", true, false},
			{0, "Setup Communication", false, false},
			{0x28, "PLC Control", false, true}, {0x29, "PLC Stop", false, true},
		}
		f := fns[rng.Intn(len(fns))]
		attrs := map[string]any{
			"function_code": f.fc, "function_name": f.name,
			"is_write": f.w, "is_control": f.c,
		}
		if f.fc == 4 || f.fc == 5 {
			areas := []string{"DB", "MK", "PE", "PA"}
			attrs["area"] = areas[rng.Intn(len(areas))]
			attrs["address"] = fmt.Sprintf("DBX%d.%d", rng.Intn(100), rng.Intn(8))
			attrs["item_count"] = rng.Intn(10) + 1
			if rng.Intn(5) == 0 {
				attrs["db_number"] = rng.Intn(200) + 1
			}
		}
		return attrs
	}},

	// BACnet/IP — attribute keys match pkg/dp/ics/bacnet/decoder.go
	{proto: "bacnet", kind: "request", transport: "udp", dstPort: 47808, weight: 6, attrFn: func(rng *rand.Rand) map[string]any {
		type bsvc struct {
			code uint8
			name string
			w    bool
		}
		svcs := []bsvc{
			{12, "ReadProperty", false}, {14, "ReadPropertyMultiple", false},
			{15, "WriteProperty", true}, {16, "WritePropertyMultiple", true},
			{8, "WhoIs", false}, {0, "IAm", false},
		}
		s := svcs[rng.Intn(len(svcs))]
		attrs := map[string]any{
			"service_code": s.code, "service": s.name,
			"is_write": s.w, "is_critical": false,
		}
		if s.code == 12 || s.code == 14 || s.code == 15 || s.code == 16 {
			objTypes := []string{"analog-input", "analog-output", "binary-input", "binary-output", "device"}
			attrs["object_type"] = objTypes[rng.Intn(len(objTypes))]
			attrs["object_instance"] = rng.Intn(200)
			props := []string{"present-value", "object-name", "description", "status-flags"}
			attrs["property_id"] = props[rng.Intn(len(props))]
		}
		return attrs
	}},

	// OPC UA — attribute keys match pkg/dp/ics/opcua/decoder.go
	{proto: "opcua", kind: "request", transport: "tcp", dstPort: 4840, weight: 5, attrFn: func(rng *rand.Rand) map[string]any {
		type oSvc struct {
			id   uint16
			name string
			w    bool
		}
		svcs := []oSvc{
			{527, "BrowseRequest", false}, {631, "ReadRequest", false},
			{673, "WriteRequest", true}, {787, "CreateSubscriptionRequest", false},
			{826, "PublishRequest", false},
		}
		s := svcs[rng.Intn(len(svcs))]
		return map[string]any{
			"service": s.name, "is_write": s.w,
		}
	}},

	// ── IT protocols ──────────────────────────────────────────────
	// DNS — attribute keys match pkg/dp/itdpi/dns.go
	{proto: "dns", kind: "query", transport: "udp", dstPort: 53, weight: 20, attrFn: func(rng *rand.Rand) map[string]any {
		domains := []string{"scada.local", "plc-01.ot.local", "historian.corp.local", "ntp.pool.org", "updates.vendor.com", "api.cloud.example.com"}
		types := []string{"A", "AAAA", "PTR", "CNAME"}
		return map[string]any{"query_name": domains[rng.Intn(len(domains))], "query_type": types[rng.Intn(len(types))], "is_response": false}
	}},

	// TLS — attribute keys match pkg/dp/itdpi/tls.go
	{proto: "tls", kind: "client_hello", transport: "tcp", dstPort: 443, weight: 15, attrFn: synthTLSClientHello},

	// HTTP — attribute keys match pkg/dp/itdpi/http.go
	{proto: "http", kind: "request", transport: "tcp", dstPort: 80, weight: 8, attrFn: func(rng *rand.Rand) map[string]any {
		paths := []string{"/api/v1/status", "/metrics", "/health", "/api/v1/data"}
		methods := []string{"GET", "POST", "GET", "GET"}
		i := rng.Intn(len(paths))
		return map[string]any{"method": methods[i], "uri": paths[i], "host": "internal-api.local"}
	}},

	// SSH — attribute keys match pkg/dp/itdpi/ssh.go
	{proto: "ssh", kind: "version_exchange", transport: "tcp", dstPort: 22, weight: 4, attrFn: func(rng *rand.Rand) map[string]any {
		versions := []string{"SSH-2.0-OpenSSH_9.6", "SSH-2.0-OpenSSH_8.9", "SSH-2.0-dropbear_2022.83"}
		return map[string]any{"client_version": versions[rng.Intn(len(versions))]}
	}},

	// NTP — attribute keys match pkg/dp/itdpi/ntp.go
	{proto: "ntp", kind: "request", transport: "udp", dstPort: 123, weight: 5, attrFn: func(rng *rand.Rand) map[string]any {
		return map[string]any{"stratum": rng.Intn(4) + 1, "mode": 3, "version": 4}
	}},

	// SNMP — attribute keys match pkg/dp/itdpi/snmp.go
	{proto: "snmp", kind: "request", transport: "udp", dstPort: 161, weight: 3, attrFn: func(rng *rand.Rand) map[string]any {
		ops := []string{"GetRequest", "GetNextRequest", "GetBulkRequest", "SetRequest"}
		pdu := ops[rng.Intn(len(ops))]
		return map[string]any{
			"pdu_type": pdu, "community_auth": true, "community_length": 6,
			"write_operation": pdu == "SetRequest",
		}
	}},

	// RDP — attribute keys match pkg/dp/itdpi/rdp.go
	{proto: "rdp", kind: "negotiation", transport: "tcp", dstPort: 3389, weight: 2, attrFn: func(rng *rand.Rand) map[string]any {
		protos := []string{"CredSSP+TLS", "TLS", "Standard RDP"}
		p := protos[rng.Intn(len(protos))]
		attrs := map[string]any{
			"requested_protocols": p, "security_level": "high", "stage": "negotiation",
		}
		if p == "Standard RDP" {
			attrs["security_level"] = "weak"
			attrs["security_concern"] = "standard RDP security offers weak encryption and is vulnerable to MITM attacks"
		}
		return attrs
	}},

	// SMB — attribute keys match pkg/dp/itdpi/smb.go
	{proto: "smb", kind: "request", transport: "tcp", dstPort: 445, weight: 2, attrFn: func(rng *rand.Rand) map[string]any {
		cmds := []string{"NEGOTIATE", "SESSION_SETUP", "TREE_CONNECT", "CREATE", "READ", "WRITE"}
		attrs := map[string]any{"command": cmds[rng.Intn(len(cmds))]}
		if rng.Intn(3) == 0 {
			shares := []string{`\\SCADA\logs`, `\\HISTORIAN\data`, `\\ADMIN$`}
			attrs["share"] = shares[rng.Intn(len(shares))]
		}
		return attrs
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
		FlowID:     flowID,
		Proto:      sc.proto,
		Kind:       sc.kind,
		Attributes: attrs,
		Timestamp:  time.Now().UTC(),
		SrcIP:      srcIP,
		DstIP:      dstIP,
		SrcPort:    srcPort,
		DstPort:    sc.dstPort,
		Transport:  sc.transport,
	}
}

// ── Realistic protocol event generators ─────────────────────────────
// These produce events with the exact attribute keys that the real DPI
// decoders emit, so IDS rules can match them and produce genuine alerts.

// synthModbusRequest generates a Modbus/TCP request event matching the
// attribute keys from pkg/dp/ics/modbus/decoder.go.
func synthModbusRequest(rng *rand.Rand) map[string]any {
	type mbReq struct {
		fc      uint8
		isWrite bool
	}
	requests := []mbReq{
		{1, false}, {2, false}, {3, false}, {4, false}, // reads
		{5, true}, {6, true}, {15, true}, {16, true},   // writes
		{8, false},  // diagnostics
		{43, false}, // MEI
	}
	r := requests[rng.Intn(len(requests))]
	unitID := uint8(rng.Intn(10) + 1)
	txnID := uint16(rng.Intn(65535))

	attrs := map[string]any{
		"function_code":  r.fc,
		"unit_id":        unitID,
		"is_write":       r.isWrite,
		"transaction_id": txnID,
	}

	// Build a realistic MBAP+PDU frame for raw_hex
	switch r.fc {
	case 8: // Diagnostics
		sub := uint16(0)
		if rng.Intn(3) == 0 {
			sub = 1 // restart comm
			attrs["is_write"] = true
		}
		attrs["sub_function"] = sub
		names := map[uint16]string{0: "return_query_data", 1: "restart_comm", 4: "force_listen_only", 10: "clear_counters"}
		if n, ok := names[sub]; ok {
			attrs["sub_function_name"] = n
		}
		// MBAP(7) + FC(1) + sub(2) + data(2)
		frame := modbusFrame(txnID, unitID, r.fc, []byte{byte(sub >> 8), byte(sub), 0x00, 0x00})
		attrs["raw_hex"] = hex.EncodeToString(frame)
	case 43: // MEI
		attrs["mei_type"] = uint8(14)
		attrs["mei_type_name"] = "read_device_identification"
		frame := modbusFrame(txnID, unitID, r.fc, []byte{14, 1, 0})
		attrs["raw_hex"] = hex.EncodeToString(frame)
	default:
		addr := uint16(rng.Intn(1000))
		qty := uint16(rng.Intn(50) + 1)
		attrs["address"] = addr
		attrs["quantity"] = qty
		pdu := []byte{byte(addr >> 8), byte(addr), byte(qty >> 8), byte(qty)}
		if r.isWrite && (r.fc == 15 || r.fc == 16) {
			// Write multiple: add byte count + data
			byteCount := byte(qty * 2)
			if r.fc == 15 {
				byteCount = byte((qty + 7) / 8)
			}
			pdu = append(pdu, byteCount)
			for i := 0; i < int(byteCount); i++ {
				pdu = append(pdu, byte(rng.Intn(256)))
			}
		}
		frame := modbusFrame(txnID, unitID, r.fc, pdu)
		attrs["raw_hex"] = hex.EncodeToString(frame)
	}

	return attrs
}

// synthModbusException generates a Modbus exception response.
func synthModbusException(rng *rand.Rand) map[string]any {
	baseFcs := []uint8{1, 3, 5, 6, 15, 16}
	baseFc := baseFcs[rng.Intn(len(baseFcs))]
	exCodes := []uint8{1, 2, 3, 4}
	exCode := exCodes[rng.Intn(len(exCodes))]
	exNames := map[uint8]string{1: "illegal_function", 2: "illegal_data_address", 3: "illegal_data_value", 4: "server_device_failure"}
	unitID := uint8(rng.Intn(10) + 1)
	txnID := uint16(rng.Intn(65535))

	// Exception response: FC = baseFc + 128, PDU = exception code
	frame := modbusFrame(txnID, unitID, baseFc+128, []byte{exCode})

	return map[string]any{
		"function_code":         baseFc,
		"unit_id":               unitID,
		"is_write":              baseFc == 5 || baseFc == 6 || baseFc == 15 || baseFc == 16,
		"transaction_id":        txnID,
		"exception_code":        exCode,
		"exception_description": exNames[exCode],
		"raw_hex":               hex.EncodeToString(frame),
	}
}

// modbusFrame builds a Modbus/TCP MBAP header + PDU.
func modbusFrame(txnID uint16, unitID, fc uint8, pdu []byte) []byte {
	length := uint16(2 + len(pdu)) // unitID + FC + PDU
	frame := make([]byte, 7+1+len(pdu))
	frame[0] = byte(txnID >> 8)
	frame[1] = byte(txnID)
	frame[2] = 0 // protocol ID high
	frame[3] = 0 // protocol ID low
	frame[4] = byte(length >> 8)
	frame[5] = byte(length)
	frame[6] = unitID
	frame[7] = fc
	copy(frame[8:], pdu)
	return frame
}

// synthTLSClientHello generates a TLS ClientHello event matching the
// attribute keys from pkg/dp/itdpi/tls.go.
func synthTLSClientHello(rng *rand.Rand) map[string]any {
	type tlsScenario struct {
		sni     string
		version string
		ja3Hash string
		alpn    string
		suites  []uint16
	}
	scenarios := []tlsScenario{
		{sni: "historian.corp.local", version: "TLS1.2", ja3Hash: "e7d705a3286e19ea42f587b344ee6865", alpn: "http/1.1", suites: []uint16{0xc02c, 0xc02b, 0x009f, 0x009e}},
		{sni: "updates.vendor.com", version: "TLS1.3", ja3Hash: "cd08e31494816f6d85f22af6a5dbd0b2", alpn: "h2,http/1.1", suites: []uint16{0x1301, 0x1302, 0x1303}},
		{sni: "cloud.scada.io", version: "TLS1.3", ja3Hash: "a92c7b3f4d21e7c1b2a3f4e5d6c7b8a9", alpn: "h2", suites: []uint16{0x1301, 0x1302, 0x1303, 0xc02c}},
		{sni: "portal.ot.local", version: "TLS1.2", ja3Hash: "b32b06a8d4b1f6a0d5c3e7b1c88a9e02", alpn: "http/1.1", suites: []uint16{0xc014, 0xc00a, 0x0035, 0x002f}},
		{sni: "plc-01.ot.local", version: "TLS1.2", ja3Hash: "3b5074b1b5d032e5620f69f9f700ff0e", alpn: "", suites: []uint16{0x002f, 0x0035}},
	}
	s := scenarios[rng.Intn(len(scenarios))]
	return map[string]any{
		"sni":           s.sni,
		"alpn":          s.alpn,
		"tls_version":   s.version,
		"cipher_suites": s.suites,
		"ja3_hash":      s.ja3Hash,
	}
}
