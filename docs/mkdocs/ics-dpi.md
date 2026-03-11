# ICS/OT Deep Packet Inspection

containd includes native Go decoders for 15 protocols (7 ICS, 8 IT) that run in the data plane engine. The same decoder set (`DefaultDecoders()`) is shared between the live capture engine and offline PCAP analysis.

## DPI Modes

The ICS DPI engine supports two operational modes:

| Mode | Behavior |
|------|----------|
| **Learn** | Passive observation only. Traffic is inspected and profiled but never blocked. Use this mode during initial deployment to baseline normal ICS communication patterns. |
| **Enforce** | Active policy enforcement. DPI results drive firewall verdicts -- traffic that violates ICS policy rules is blocked. |

The recommended workflow is **learn first, then enforce**: deploy in learn mode, review the generated traffic profiles and auto-generated allowlist rules, tune as needed, then switch to enforce mode.

Configure via the UI (DPI Configuration section on the Firewall page), the API (`POST /api/v1/engine/config` with `dpiMode`), or the CLI (`set dpi mode learn|enforce`).

## Per-Protocol Enable/Disable

Each ICS protocol decoder can be individually enabled or disabled. This allows you to activate inspection only for protocols present in your environment, reducing processing overhead.

Configure via the UI (ICS DPI Configuration modal on the Firewall page) or the API (`dpiIcsProtocols` map in `POST /api/v1/engine/config`):

```json
{
  "dpiMode": "enforce",
  "dpiIcsProtocols": {
    "modbus": true,
    "dnp3": true,
    "cip": false,
    "s7comm": false,
    "mms": true,
    "bacnet": false,
    "opcua": false
  }
}
```

## Protocol Decoders

### ICS Protocols

| Protocol | Port | Package | Key Fields |
|----------|------|---------|------------|
| Modbus/TCP | 502 | `pkg/dp/ics/modbus` | Unit ID, function code, address, quantity, payload length, read/write classification |
| DNP3 | 20000 | `pkg/dp/ics/dnp3` | Source/destination station addresses, function code, object headers, data link layer |
| CIP/EtherNet/IP | 44818 | `pkg/dp/ics/cip` | Service code, class/instance/attribute, EPATH parsing, MSP sub-service parsing, object classes |
| S7comm | 102 | `pkg/dp/ics/s7comm` | PDU type, function code, DB number, parameter/data fields |
| IEC 61850 MMS | 102 | `pkg/dp/ics/iec61850` | MMS service type, named variables, domain references |
| BACnet | 47808 | `pkg/dp/ics/bacnet` | APDU type, service choice, object identifier, object type, property ID |
| OPC UA | 4840 | `pkg/dp/ics/opcua` | Message type, service request/response, node IDs |

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
3. **Protocol detection** -- `DefaultDecoders()` are tried in order; port-based detection and an ICS marker identify protocol type. Only enabled protocols are evaluated.
4. **Verdict caching** -- once a flow is classified, the verdict is cached to avoid redundant inspection.
5. **Event emission** -- DPI events feed into IDS rules, anomaly detection, signature matching, asset inventory, learn mode, protocol statistics, and event export.

## ICS Firewall Rule Predicates

Firewall rules support protocol-specific conditions. Each ICS protocol exposes different predicate fields matching its data model:

### Modbus
- Function code (e.g., `1` Read Coils, `3` Read Holding Registers, `5` Write Single Coil, `6` Write Single Register, `15` Write Multiple Coils, `16` Write Multiple Registers)
- Unit ID (0--247)
- Read-only / Write-only classification
- Address ranges

### DNP3
- Function code (e.g., `1` Read, `2` Write, `3` Select, `4` Operate, `13` Cold Restart, `14` Warm Restart)
- Source and destination station addresses (0--65519)
- Object headers

### CIP/EtherNet/IP
- Service code (e.g., `0x01` Get Attribute All, `0x0E` Create, `0x4C` Read Tag, `0x4D` Write Tag, `0x52` Read Tag Fragmented)
- Object class/instance/attribute
- EPATH expressions
- MSP sub-service matching

### S7comm
- Function code (e.g., `0x04` Read Var, `0x05` Write Var, `0xF0` Setup Communication)
- DB number

### IEC 61850 MMS
- MMS service type
- Named variable references
- Domain references

### BACnet
- Service choice
- Object type (Analog Input, Analog Output, Binary Input, etc.)
- Property ID (Present Value, Status Flags, etc.)
- Object identifier

### OPC UA
- Message type
- Service request/response type
- Node ID patterns

## ICS Asset Auto-Discovery

The inventory module (`pkg/dp/inventory`) passively identifies ICS assets from observed traffic. Discovered assets include IP address, protocol, device type (when identifiable), and first/last seen timestamps. The inventory is accessible via `GET /api/v1/inventory`.

## Learn Mode

The learn module (`pkg/dp/learn`) records traffic profiles during a learning period. Once sufficient data is collected, it generates allowlist firewall rules that match observed behavior. The workflow is:

1. Set DPI mode to **learn** via the UI or API.
2. `GET /api/v1/learn/profiles` -- view current traffic profiles.
3. `POST /api/v1/learn/generate` -- generate candidate rules from profiles.
4. Review generated rules in the UI firewall page.
5. `POST /api/v1/learn/apply` -- apply generated rules to the firewall config.
6. Switch DPI mode to **enforce**.
7. `DELETE /api/v1/learn` -- clear learned profiles when no longer needed.

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

## ICS Policy Templates

Seven ICS protocol templates are available via `GET /api/v1/templates/ics` and can be applied with `POST /api/v1/templates/ics/apply`. Templates provide baseline configurations for common ICS environments including Purdue model zones and maintenance window policies.
