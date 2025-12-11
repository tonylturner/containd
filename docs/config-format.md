# Config Format

Canonical JSON configuration for export/import and persistent state.

## Schema (initial)

```jsonc
{
  "version": "0.1.0",
  "description": "optional",
  "system": {
    "hostname": "containd"
  },
  "zones": [
    { "name": "it", "description": "IT network" },
    { "name": "dmz", "description": "DMZ" }
  ],
  "interfaces": [
    { "name": "eth0", "zone": "it", "addresses": ["192.168.1.1/24"] },
    { "name": "eth1", "zone": "dmz", "addresses": ["10.0.0.1/24"] }
  ],
  "firewall": {
    "defaultAction": "ALLOW",
    "rules": [
      {
        "id": "1",
        "description": "IT to DMZ",
        "sourceZones": ["it"],
        "destZones": ["dmz"],
        "sources": ["192.168.1.0/24"],
        "destinations": ["10.0.0.0/24"],
        "protocols": [{ "name": "tcp", "port": "80" }],
        "action": "ALLOW"
      }
    ]
  }
}
```

Notes:
- `zones` must be unique.
- `interfaces.zone` must reference an existing zone; addresses are CIDR strings.
- `firewall.rules` must have unique `id`; action is `ALLOW` or `DENY`.
- `protocols.port` accepts single ports or ranges (`"443"` or `"1000-2000"`).
