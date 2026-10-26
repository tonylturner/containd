# Config Format

Canonical JSON configuration for export/import and persistent state. The config
schema version is independent of the containd release version.

Imports stage a candidate; commit is required to activate it. Failed commit,
commit-confirmed or rollback restores and reapplies the pre-request running
document and IDS bank while retaining the candidate. Inspect the error body's
`restored`/`reapplied` fields rather than assuming recovery succeeded. Nft
ruleset failures are fatal, including missing `NET_ADMIN`; see the
[Orchestrator Client Contract](api-reference.md#orchestrator-client-contract).
Keep `dataplane.enforcement: true` to install firewall rules. The example below
shows the existing intentionally disabled mode, which only applies an in-memory
snapshot and cannot certify nft enforcement.

## Schema

This complete example uses schema `0.1.7`. It defines two routed networks and a
single TCP/80 allow rule. With enforcement enabled, other new forwarded
connections are denied. Enforcement is off until you enable it deliberately. Replace the illustrative kernel devices and
addresses with your deployment's values before applying it. This is not the
Docker starter topology.

```json
{
  "schema_version": "0.1.7",
  "description": "Two-zone routed lab; adapt device names and addressing before committing",
  "system": {
    "hostname": "containd",
    "mgmt": {
      "listenAddr": ":8080",
      "enableHTTP": true,
      "enableHTTPS": true,
      "httpListenAddr": ":8080",
      "httpsListenAddr": ":8443",
      "tlsCertFile": "/data/tls/server.crt",
      "tlsKeyFile": "/data/tls/server.key"
    },
    "ssh": {
      "listenAddr": ":2222",
      "authorizedKeysDir": "/data/ssh/authorized_keys.d",
      "allowPassword": false
    }
  },
  "zones": [
    {
      "name": "it",
      "description": "IT network"
    },
    {
      "name": "dmz",
      "description": "DMZ"
    }
  ],
  "interfaces": [
    {
      "name": "it",
      "zone": "it",
      "addresses": [
        "192.168.1.1/24"
      ],
      "access": {
        "mgmt": true,
        "http": true,
        "https": true,
        "ssh": false
      },
      "device": "eth0"
    },
    {
      "name": "dmz",
      "zone": "dmz",
      "addresses": [
        "10.0.0.1/24"
      ],
      "access": {
        "mgmt": false,
        "http": false,
        "https": false,
        "ssh": false
      },
      "device": "eth1"
    }
  ],
  "dataplane": {
    "captureInterfaces": [
      "eth0",
      "eth1"
    ],
    "enforcement": false,
    "enforceTable": "containd",
    "dpiMock": false
  },
  "routing": {
    "routes": [
      {
        "dst": "203.0.113.0/24",
        "gateway": "192.168.1.254",
        "iface": "it",
        "table": 0,
        "metric": 100
      }
    ]
  },
  "assets": [
    {
      "id": "plc-1",
      "name": "Boiler PLC",
      "type": "PLC",
      "zone": "dmz",
      "ips": [
        "10.0.0.10"
      ],
      "hostnames": [
        "plc1.lab.local"
      ],
      "criticality": "HIGH",
      "tags": [
        "boiler",
        "line-1"
      ]
    }
  ],
  "services": {
    "syslog": {
      "forwarders": [
        {
          "address": "192.0.2.10",
          "port": 514,
          "proto": "udp"
        }
      ]
    },
    "dns": {
      "enabled": false
    },
    "ntp": {
      "enabled": false
    },
    "dhcp": {
      "enabled": false
    },
    "vpn": {
      "wireguard": {
        "enabled": false
      },
      "openvpn": {
        "enabled": false
      }
    }
  },
  "firewall": {
    "defaultAction": "DENY",
    "nat": {
      "enabled": false
    },
    "rules": [
      {
        "id": "1",
        "description": "IT web access to DMZ",
        "sourceZones": [
          "it"
        ],
        "destZones": [
          "dmz"
        ],
        "sources": [
          "192.168.1.0/24"
        ],
        "destinations": [
          "10.0.0.0/24"
        ],
        "protocols": [
          {
            "name": "tcp",
            "port": "80"
          }
        ],
        "action": "ALLOW"
      }
    ]
  }
}
```

Notes:
- Serialized firewall rules always include `ics`; `{}` means the rule has no
  ICS predicate. Input rules may omit this field.
- `zones` must be unique.
- `interfaces.zone` must reference an existing zone; addresses are CIDR strings.
- `pcap.interfaces` accepts logical interface names or kernel device names. Logical names resolve to their configured device (or the logical name when no device is set).
- `pcap.zones` captures every configured interface assigned to each listed zone; interface and zone selections are combined and deduplicated when capture starts.
- `pcap.filter.port` accepts one port (for example `"2404"`) or an inclusive range (for example `"1000-2000"`). It matches source or destination ports in TCP/UDP packets; it cannot be combined with `proto: "icmp"`.
- The live capture filter currently parses untagged Ethernet IPv4. Non-initial IPv4 fragments do not expose ports and therefore do not match a port filter.
- Capture start rejects unknown interfaces or zones, zones with no configured interfaces, and an empty selection. `GET /api/v1/pcap/status` reports the resolved kernel devices.
- `interfaces.addressMode` supports `static` (explicit CIDRs) and `dhcp` (best-effort; Docker commonly preconfigures IPs without DHCP).
- `interfaces.type` supports `physical` (default), `bridge` (with `members`), and `vlan` (with `parent` + `vlanId`).
- `interfaces.access` controls whether mgmt/ssh is reachable on that interface (omitted access settings use the default grants; localhost is always allowed).
- `services.dhcp` configures the built-in DHCP server. `authoritative` is a persisted boolean, default false when omitted. Requests for addresses this server cannot lease receive DHCPNAK only when authoritative, on directly attached served subnets; otherwise they receive no reply. Eligible INIT-REBOOT and renewal/rebinding requests receive DHCPACK and record a lease in both modes, even without a prior lease; relayed requests and requests selecting another server are ignored.
- `services.ntp.intervalSeconds` pins chrony polling when positive: round up to a power of two and clamp to 16–131072 seconds. Omitted or zero retains adaptive 64–1024 second polling. Runtime status reports the configured fixed interval (or null for adaptive polling) and min/max seconds; initial bursts may be faster.
- `services.vpn.wireguard` configures WireGuard. `services.vpn.openvpn` supports managed client/server modes.
- `services.vpn.openvpn.server.tunnelCIDR` is the client address pool allocated by the OpenVPN server. WireGuard uses static peer `AllowedIPs` and `addressCIDR` for policy targeting.
- Config backups are stored beside the config DB in `config-backups/` (normally `/data/config-backups/` in Compose) and can be created redacted or full (admin-only for unredacted).
- `assets` must have unique `id` and `name`; `zone` must reference an existing zone if set; `ips` are IPv4/IPv6 strings; `type` and `criticality` are enumerated strings.
- `dataplane` controls runtime capture/enforcement; values are pushed to the engine on commit/rollback.
- `routing` configures kernel routing when applying running config:
  - `routes` are installed via netlink (Linux only; IPv4 only). Route `table: 0`
    selects main; explicit tables use IDs 1–252.
  - `rules` are installed via netlink as basic policy-based routing (Linux only;
    src/dst CIDR selection, table IDs 1–252). Explicit priorities use 1–65535;
    priority 0 selects automatic priority starting at 10000. The reserved
    management path can reject overlapping rules at priority 1.
  - Every running-config apply converges entries marked with protocol 98,
    including deletion and empty intent. Identical foreign entries satisfy intent
    without taking ownership. A foreign route with the same destination, table,
    TOS and metric but a different next hop is journaled, replaced, and restored
    when that route leaves intent. Unsupported collisions fail with route details.
    See [routing ownership and upgrades](dataplane.md#routing-ownership-and-upgrades).
- `firewall.defaultAction` applies to forwarded traffic that no rule matches. It is `ALLOW` or `DENY`; omitted or empty means `DENY`, and any other value is rejected.
- `firewall.rules` must have unique `id`; action is `ALLOW` or `DENY`.
- Firewall rule objects reject unknown and duplicate keys. Key spelling is exact; decoding errors identify the rule ID when available. This applies to full config, candidate, import, and rule patch JSON.
- `firewall.nat.enabled` enables source NAT (masquerade) from `sourceZones` out
  `egressZone` (defaults: `lan`/`dmz` out `wan`). Only zones with bound interfaces
  generate matches; custom zone names are supported.
- Each enabled `firewall.nat.portForwards` entry translates traffic arriving in
  its `ingressZone` to `destIp`/`destPort`; disabled entries generate no rules.
  The ingress zone must have bound interfaces. When source NAT is enabled,
  forwarded DNAT traffic is masqueraded only for that entry's translated target,
  using the route-selected egress interface rather than an assumed `lan` zone.
  The destination sees the firewall's egress address, ensuring a return path.
  Port-forward enablement is independent of `firewall.nat.enabled`; disabling
  source NAT leaves DNAT enabled and requires a routed return path.
- `protocols.port` accepts single ports or ranges (`"443"` or `"1000-2000"`).
- Syslog forwarders require address and port; proto `udp` or `tcp` (defaults to udp if empty).

Limitations:
- Routing/PBR supports IPv4 only. Unmarked rules installed before protocol-based
  ownership require manual upgrade cleanup; see the routing ownership guide.
- NAT supports postrouting masquerade and DNAT/port-forwarding.

## Configuration lifecycle

Saving or importing validates and replaces the **candidate**; it does not change
the running appliance. Review the running/candidate diff, then commit to promote
and apply the candidate to the engine and services. A confirmed commit requires
confirmation before its deadline or the previous configuration is restored.
Rollback restores the previous running configuration. With a reserved management
path, unsafe changes and rollback targets are refused; see
[Reserved Management Path](management-reservation.md).

Exports are redacted by default. Only admins can request an unredacted export;
store full backups securely. Keep the persistent data volume as well as exported
JSON if you need users, audit history, or service files during recovery.

## Additional CA bundle

`system.mgmt.trustedCAFile` selects the PEM bundle storage path, defaulting to
`/data/tls/trusted_ca.pem`. Uploads require a path under `/data`.
`POST /api/v1/system/tls/trusted-ca` is an immediate admin operation, not a
candidate edit:

- `{"pem":"-----BEGIN CERTIFICATE-----\n..."}` replaces the entire bundle.
  Every block must parse as an X.509 CA certificate with valid CA basic
  constraints. Root and intermediate CA certificates are accepted; leaf
  certificates, non-certificate blocks, malformed PEM and empty bundles are not.
- `{"clear":true}` clears the stored bundle. Do not combine it with nonblank PEM.
- A rejected upload leaves the previous file unchanged. Successful replacement
  is atomic, so readers cannot observe a partially written bundle.

**Runtime limitation:** storing this bundle does not yet configure outbound TLS
clients or external service daemons to use it. An upload's `updated` response
confirms storage only, not endpoint trust. See [security limits](secure-by-design.md#additional-ca-bundle-storage).

## API endpoints

See [API Reference](api-reference.md) for endpoints and the OpenAPI wire contract.
Configuration lifecycle and JSON examples are maintained on this page.

## Runtime connections

The Sessions page and `GET /api/v1/conntrack` show the kernel's IPv4 and IPv6
connections, including original and reply NAT tuples. A successful empty array
is a verified empty table; unavailable or interrupted netlink dumps return an
error with the backend reason. The engine needs Linux conntrack support and
`NET_ADMIN` in the traffic's network namespace. The list is capped at 5,000 rows.

Admins use `POST /api/v1/conntrack/kill` with the displayed original TCP or UDP
tuple (`proto`, `src`, `dst`, `sport`, `dport`). `scope: connection` (default)
revokes only that exact connection in both directions; reconnecting from a fresh
source port is allowed. `scope: client-service` ends all that client's
connections to the original destination service and prevents reconnects for the
interval. Neighbouring clients, services and transports remain unaffected.
`durationSecs` is 1–3600 seconds, default 60. These are runtime operations, not
candidate configuration changes, and require active nftables enforcement.

The response reports `revocationInstalled`, `blockedUntil`, `conntrackDeleted`
and counts/errors independently. Revocation is installed atomically before
state deletion. Matching TCP packets receive kernel-generated resets on each
endpoint's next packet; this is not confirmed endpoint closure. Matching UDP
packets are dropped. A failed revocation does not delete kernel state. Inspect
each step even on HTTP 200. ICMP and other protocols are visible but cannot be
killed through this port-based API.

Revocations are kernel runtime state. Replacing the firewall ruleset or
restarting the appliance clears them; they are not persisted configuration.
