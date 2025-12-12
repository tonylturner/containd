# ICS DPI Plan

This document tracks the plan for ICS protocol decoding, DPI events, and how DPI feeds the rule/IDS engines.

## Decoders (phased)
- Phase 3: Modbus/TCP decoder (unit ID, function code, address, quantity, payload length).
  - Skeleton decoder now lives in `pkg/dp/ics/modbus` and is ready to be wired into capture.
- Phase 4+: DNP3, IEC-60870-5-104, S7comm/Profinet, CIP/EtherNet/IP, OPC UA (basic node/service info).

## Interfaces
`pkg/dp/dpi` should expose:
```go
type Decoder interface {
    Supports(flow *Flow) bool
    OnPacket(flow *Flow, pkt *ParsedPacket) ([]Event, error)
    OnFlowEnd(flow *Flow) ([]Event, error)
}

type Event struct {
    FlowID     string
    Proto      string
    Kind       string
    Attributes map[string]any
    Timestamp  time.Time
}
```

## Integration points
- Data-plane workers feed TCP reassembly → DPI decoders.
- DPI events enrich flow context and feed:
  - Rule engine (ICS-aware conditions in `pkg/dp/rules`).
  - IDS engine (signature/behavioral detection).
  - Telemetry/export (e.g., syslog/alert streams).

## Policy hooks
- Rule conditions should allow matching on protocol (`modbus`, `dnp3`, etc.) and attributes (e.g., `modbus.function_code`, address ranges).
- IDS rules can match on DPI attributes and flow frequency/sequence.

## Telemetry/logging
- DPI events should be serialized in a compact format for syslog forwarding and API retrieval.
- Consider sampling to avoid overwhelming management plane.

## Testing approach
- Protocol-specific fixture packets for each decoder.
- Unit tests for parsing function codes/fields.
- Integration tests that assert events flow into rule evaluation/IDS pipeline once implemented.
