# ICS/OT Deep Packet Inspection

containd includes native Go decoders for 15 protocols (7 ICS, 8 IT) that run in the data plane engine. The same decoder set (`DefaultDecoders()`) is shared between the live capture engine and offline PCAP analysis.

## Protocol Decoders

### ICS Protocols

| Protocol | Package | Key Fields |
|----------|---------|------------|
| Modbus/TCP | `pkg/dp/ics/modbus` | Unit ID, function code, address, quantity, payload length, read/write classification |
| DNP3 | `pkg/dp/ics/dnp3` | Source/destination addresses, function code, object headers, data link layer |
| CIP/EtherNet/IP | `pkg/dp/ics/cip` | Service code, class/instance/attribute, EPATH parsing, MSP sub-service parsing |
| S7comm | `pkg/dp/ics/s7comm` | PDU type, function code, parameter/data fields |
| IEC 61850 MMS | `pkg/dp/ics/iec61850` | MMS service type, named variables, domain references |
| BACnet | `pkg/dp/ics/bacnet` | APDU type, service choice, object identifier |
| OPC UA | `pkg/dp/ics/opcua` | Message type, service request/response, node IDs |

### IT Protocols

| Protocol | Package | Key Fields |
|----------|---------|------------|
| DNS | `pkg/dp/dpi/it` | Query name, type, response code, compression pointer support |
| TLS | `pkg/dp/dpi/it` | SNI, JA3 fingerprint, TLS version, cipher suites |
| HTTP | `pkg/dp/dpi/it` | Method, URI, host, status code, content type |
| SSH | `pkg/dp/dpi/it` | Version string, key exchange algorithms |
| SMB | `pkg/dp/dpi/it` | Command, dialect, share name |
| NTP | `pkg/dp/dpi/it` | Stratum, reference ID, mode |
| SNMP | `pkg/dp/dpi/it` | Version, community, PDU type, OIDs |
| RDP | `pkg/dp/dpi/it` | Protocol version, security flags |

## Decoder Interface

`pkg/dp/dpi` exposes:
```go
type Decoder interface {
    Supports(state *flow.State) bool
    OnPacket(state *flow.State, pkt *ParsedPacket) ([]Event, error)
    OnFlowEnd(state *flow.State) ([]Event, error)
}

type Event struct {
    FlowID     string
    Proto      string
    Kind       string
    Attributes map[string]any
    Timestamp  time.Time
}
```

## DPI Pipeline

The data plane processes packets through a multi-stage pipeline:

1. **NFQUEUE steering** -- only flows matching DPI criteria are diverted to userspace; all other traffic follows the nftables fast path.
2. **TCP reassembly** -- out-of-order segments are buffered and reassembled before feeding decoders.
3. **Protocol detection** -- `DefaultDecoders()` are tried in order; port-based detection and an ICS marker identify protocol type.
4. **Verdict caching** -- once a flow is classified, the verdict is cached to avoid redundant inspection.
5. **Event emission** -- DPI events feed into IDS rules, anomaly detection, signature matching, asset inventory, learn mode, protocol statistics, and event export.

## ICS Asset Auto-Discovery

The inventory module (`pkg/dp/inventory`) passively identifies ICS assets from observed traffic. Discovered assets include IP address, protocol, device type (when identifiable), and first/last seen timestamps. The inventory is accessible via `GET /api/v1/inventory`.

## Learn Mode

The learn module (`pkg/dp/learn`) records traffic profiles during a learning period. Once sufficient data is collected, it generates allowlist firewall rules that match observed behavior. The workflow is:

1. `GET /api/v1/learn/profiles` -- view current traffic profiles.
2. `POST /api/v1/learn/generate` -- generate candidate rules from profiles.
3. `POST /api/v1/learn/apply` -- apply generated rules to the firewall config.
4. `DELETE /api/v1/learn` -- clear learned profiles.

## Anomaly Detection

The anomaly detector (`pkg/dp/anomaly`) identifies:

- Malformed protocol frames
- Protocol specification violations
- Rate anomalies (unusual traffic volume or frequency)

Anomalies are accessible via `GET /api/v1/anomalies`.

## Signature-Based IDS

The signature engine (`pkg/dp/signatures`) ships with 16 built-in ICS malware signatures. Custom signatures can be added via the API:

- `GET /api/v1/signatures` -- list loaded signatures.
- `POST /api/v1/signatures` -- add a custom signature.
- `DELETE /api/v1/signatures/:id` -- remove a signature.
- `GET /api/v1/signatures/matches` -- list signature match events.

## PCAP Offline Analysis

Upload a PCAP file for offline DPI processing and automatic policy generation:

- `POST /api/v1/pcap/analyze` -- upload and analyze a PCAP file.
- `POST /api/v1/pcap/analyze/:name` -- analyze a previously uploaded PCAP by name.

The analysis runs the same `DefaultDecoders()` pipeline used by the live engine, producing DPI events, asset inventory updates, and candidate firewall rules.

## Event Export

DPI and security events can be exported in multiple formats (`pkg/dp/export`):

- **CEF** -- ArcSight Common Event Format
- **JSON** -- structured JSON
- **Syslog** -- RFC 5424

Export destinations include file, UDP, and TCP endpoints.

## Protocol Statistics

The stats module (`pkg/dp/stats`) tracks per-protocol traffic counters and identifies top talkers:

- `GET /api/v1/stats/protocols` -- protocol breakdown.
- `GET /api/v1/stats/top-talkers` -- top source/destination pairs by volume.

## Policy Hooks

Firewall rules support ICS-aware conditions:

- Protocol matching (`modbus`, `dnp3`, `cip`, `s7comm`, `mms`, `bacnet`, `opcua`)
- Attribute-level conditions (e.g., `modbus.function_code`, address ranges, read-only/write-only)
- Schedule predicates for time-based rule activation
- Identity predicates for user-based access control

IDS rules can match on any DPI attribute and flow frequency/sequence. See [IDS Rules](ids-rules.md) for details.

## ICS Policy Templates

Seven ICS protocol templates are available via `GET /api/v1/templates/ics` and can be applied with `POST /api/v1/templates/ics/apply`. Templates provide baseline configurations for common ICS environments including Purdue model zones and maintenance window policies.
