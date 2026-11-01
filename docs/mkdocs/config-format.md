# Config Format

Canonical JSON configuration for export/import and persistent state. The config
schema version is independent of the containd release version.

Full-config writes and validation reject unknown or duplicate top-level keys.
Names are case-sensitive: use `dataplane` and `schema_version`, not `dataPlane`
or `schemaVersion`. HTTP 400 responses name the offending key and suggest the
canonical spelling when it differs only by case. Nested-section compatibility
is unchanged.

Imports stage a candidate; commit is required to activate it. Failed commit,
commit-confirmed or rollback attempts to restore and reapply the pre-request
running document and IDS bank while retaining the candidate. Inspect the error body's
`restored`/`reapplied` fields rather than assuming recovery succeeded. Nft
ruleset failures are fatal, including missing `NET_ADMIN`; see the
[Orchestrator Client Contract](api-reference.md#orchestrator-client-contract).
Keep `dataplane.enforcement: true` to install firewall rules. The example below
shows the intentionally disabled mode, which updates the engine's in-memory
snapshot without installing firewall rules. Interface and service configuration
can still change.

Stored-state replay, rollback and commit confirmation tolerate service-only
faults by applying an in-memory effective configuration. They still refuse
invalid firewall, scan-selection or management-path policy. The stored document
is preserved, including quarantined service settings.

Candidate saves, imports and commits reject new service faults. They permit a
fault only when the running document already faults that service and its section
is unchanged. This lets an operator repair firewall policy without first fixing
an unrelated service. New defaults and factory resets require fault-free
configuration. Validation previews use the same write rule. Schema migrations
preserve historical service content; boot repairs may change interface bindings
and management defaults but may not change service sections.
See [Service faults](services.md#service-faults) for status and protection effects.

## Schema

The current schema is `0.1.10`. Back up before upgrading: 0.1.36 and earlier
cannot read schema 0.1.10; restore a pre-upgrade backup to downgrade.
See [ordered policy upgrades](#ordered-policy-upgrades) for rule-order and
port-forward migration behavior.

This complete example uses schema `0.1.10`. It defines two routed networks and a
single TCP/80 allow rule. With enforcement enabled, other new forwarded
connections are denied. Enforcement is off until you enable it deliberately. Replace the illustrative kernel devices and
addresses with your deployment's values before applying it. This is not the
Docker starter topology.

```json
{
  "schema_version": "0.1.10",
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
- `zones` must be unique. A zone name is 1 to 125 bytes without leading or
  trailing whitespace; enforcement names each zone's nftables interface set
  after it.
- `interfaces.zone`, when set, must reference an existing zone; addresses are CIDR strings.
- `interfaces.device`, or the `name` of an interface without a device (which is then its kernel name), must be a Linux interface name that nftables can match exactly: 1–15 bytes, without `/`, `:`, whitespace, control characters, `"`, `*` or `\`, and neither `.` nor `..`. So must each `services.dhcp.listenIfaces` entry of an enabled DHCP server that names a kernel device rather than a configured interface.
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
  - `enforceTable` names the engine's nftables tables (default `containd`): `inet <enforceTable>` holds temporary blocks and connection revocations, and `inet <enforceTable>_policy` holds the firewall policy. The name starts with a letter or `_`, continues with letters, digits, `_` or `-`, and has at most 248 characters. It must not be an nft keyword such as `table`, `inet`, `ip`, `accept` or `drop`, which nft cannot address as a table name even quoted; keywords are lowercase, so `Table` is accepted. `containd_dhcp` is reserved for the DHCP redirect table.
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
- `firewall.rules` must have unique `id`; `action` is `ALLOW`, `DENY`, `RESET`, `RATE_LIMIT` or `TAG` (see [Actions and precedence](policy-model.md#actions-and-precedence)). The first matching enforcing terminal rule in configured order wins; otherwise firewall.defaultAction applies. Monitor rules never decide.
  - `RATE_LIMIT` needs `rateLimit`: `{"packetsPerSecond": 100, "burst": 20}`, with `packetsPerSecond` 1–1000000 and `burst` 0–1000000 packets (0 means `packetsPerSecond`). Other actions reject `rateLimit`.
  - `TAG` needs `tag`, matching `^[a-z0-9][a-z0-9_.-]{0,31}$`, and takes no `schedule`; a config uses at most 32 distinct labels. Other actions reject `tag`.
  - `RESET`, `RATE_LIMIT` and `TAG` reject an `ics.protocol`; `RESET` is not a valid `firewall.defaultAction`.
  - `viaForwards` limits a rule to connections translated by any of the named
    port forwards. Every ID must exist in `firewall.nat.portForwards`; ordinary
    routed traffic to the same backend does not match this selector.
- Firewall rule objects, and their `rateLimit` objects, reject unknown and duplicate keys. Key spelling is exact; decoding errors identify the rule ID when available. This applies to full config, candidate, import, and rule patch JSON.
- `firewall.identityBindings` tags source addresses with identity labels for
  rule `identities`: `[{"ip": "10.0.0.5", "identities": ["operator"]}]`. Each
  entry binds one unicast IPv4 or IPv6 address, without a zone, at most once
  (an IPv4-mapped IPv6 address is its IPv4 address), to 1–16 distinct labels.
  A label is 1–64 bytes of printable UTF-8 without surrounding spaces. A
  configuration holds at most 4096 bindings. `/api/v1/identities` edits them in
  the candidate; see
  [Identity and schedule predicates](policy-model.md#identity-and-schedule-predicates).
- A rule `schedule` has `daysOfWeek` (`Sunday`…`Saturday`, empty for every day),
  `startTime` and `endTime` (24-hour `HH:MM`) and an IANA `timezone` (blank is
  UTC). Equal start and end times are rejected. Zone data ships with containd.
- `firewall.nat.enabled` enables source NAT (masquerade) from `sourceZones` out
  `egressZone` (default `wan`). When `sourceZones` is empty, configuration
  compilation selects every configured zone except the egress zone. Only zones
  with bound interfaces generate matches; custom zone names are supported.
- Each enabled `firewall.nat.portForwards` entry translates traffic arriving in
  its `ingressZone` to `destIp`/`destPort`; disabled entries generate no rules.
  The ingress zone must have bound interfaces. When source NAT is enabled,
  forwarded DNAT traffic is masqueraded only for that entry's translated target,
  using the route-selected egress interface rather than an assumed `lan` zone.
  The destination sees the firewall's egress address, ensuring a return path.
  Port-forward enablement is independent of `firewall.nat.enabled`; disabling
  source NAT leaves DNAT enabled and requires a routed return path.
  Translation does not grant firewall admission; see
  [Port-forward publication and deletion](policy-model.md#port-forward-publication-and-deletion).
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

Restore old JSON backups with `POST /api/v1/config/import`. Only this endpoint
accepts the retired top-level `export` section for schemas `0.1.0`–`0.1.7`
(a missing schema means `0.1.0`), discarding it during migration. Other unknown
or duplicate top-level keys are rejected, as is `export` on newer schemas.
Ordinary config saves and validation do not accept `export`, even for old
schemas. Correct rejected keys and retry; a rejected import leaves the
candidate and running configuration unchanged.

## Ordered policy upgrades

Loading, importing or committing a configuration below schema `0.1.10` upgrades
it to ordered first-match policy. Potentially overlapping terminal rules are
reordered to preserve legacy precedence (ALLOW first, then DENY/RESET, ordered
by ID within each group); rules proven disjoint retain authored order where
possible. Rule reordering leaves `RATE_LIMIT` and `TAG` in their slots; generated
forward grants can shift rule positions. Running, candidate and previous banks
record their before/after rule IDs in durable
`config.ordered_policy.migrated` audit records.

Port forwards now translate only; firewall policy decides admission. For each
forward not already referenced by a `viaForwards` rule, migration generates a
forward-scoped ALLOW before existing terminals only when no enforcing ICS
transport scope overlaps. Full containment in an enforcing ICS scope generates
no grant. Partial or uncertain overlap generates no grant for **any** of that
forward's traffic, even outside the inspected subset, and records a warning.
Existing inspection rules and defaults still decide delivery, so migration does
not promise to preserve every former port-forward admission. Review rule order
and warnings before relying on a published service. See
[port-forward publication](policy-model.md#port-forward-publication-and-deletion)
for placement explanations and explicit permission authoring.

## Unsupported protocols during upgrade

When a saved configuration with schema below `0.1.8` is loaded, exact matches
to shipped built-in IDS rules for removed industrial protocols are removed
automatically; only the `enabled` setting may differ. Containd records the
removed rule IDs in an audit record when it persists the migrated configuration.
Edited copies and other references are not removed. A remaining reference to a
removed protocol starts the appliance in **management recovery**; the saved
configuration remains exportable, and committing a valid configuration repairs
the appliance.

The management API returns HTTP 400 with the applicable message below when a
new configuration contains an unsupported industrial protocol. Rejected
stage, import, commit, or rollback requests are all-or-nothing and do not
partially apply changes:

```text
rule <id> ics protocol "<name>" is not supported; supported: modbus, dnp3, iec104, cip
dataplane.dpiIcsProtocols: protocol "<name>" is not supported; supported: modbus, dnp3, iec104, cip
ids rule <id> proto "<name>" is not supported; supported: modbus, dnp3, iec104, cip
signature <id> protocol "<name>" is not supported; supported: modbus, dnp3, iec104, cip
```

The saved configuration is not silently rewritten beyond the unchanged
built-in IDS rules above. Correct other unsupported references and commit the
valid configuration to leave management recovery.

## Management HTTPS identity

When `system.mgmt.tlsCertFile` and `tlsKeyFile` are empty or resolve to the
legacy defaults `/data/tls/server.crt` and `/data/tls/server.key`, containd owns
one bundle: `/data/tls/server.pem` (mode 0600). The example above selects this
managed mode; no new configuration field is needed. The bundle contains the
certificate chain, leaf first, followed by its matching private key.

At first start without a bundle, containd imports a valid default-path legacy
pair. Missing or mismatched legacy files cause a fresh self-signed bundle to be
generated, with a log message. The legacy files remain untouched for downgrade.
Once a bundle exists, legacy files are ignored; an unreadable or invalid bundle
refuses HTTPS rather than overwriting the identity. Factory reset preserves both
TLS bytes and the saved managed/external choice.

Admins replace the managed identity with
`POST /api/v1/system/tls/cert`, sending `{"certPEM":"...","keyPEM":"..."}`.
The pair is validated and published with one durable atomic rename; the listener
reads the bundle once at each reload. Failures before rename preserve the old
bundle. A failure to sync the directory after rename returns HTTP 500 with
**commit uncertain**: the new bundle is visible but its crash durability is not
confirmed. Inspect status before retrying; containd does not roll it back.
A successful upload reports `updated` when the bound HTTPS listener serves the
bundle, or `stored` with a warning when it takes effect at the next start.
Uploads never change saved paths.

Handshakes check each file's device/inode, size and modification time. Unchanged
files are not reread or reparsed, including invalid replacements: status keeps
the remembered error and last-good public leaf until another identity change.
An in-progress reload does not block other handshakes from using the last-good
snapshot. Use atomic replacement for rotation; edits preserving all of those
metadata fields are not detected.

`CONTAIND_TLS_CERT_FILE` and `CONTAIND_TLS_KEY_FILE` override the corresponding
saved paths independently. Any resolved nondefault path selects **external,
read-only mode**, even under `/data`: containd never writes, chmods or generates
these files. Upload returns HTTP 409 naming the override and how to return to
managed mode. Unset both environment overrides and clear both saved paths (or
restore their legacy defaults) to enable managed uploads again.

For atomic external rotation, set **both paths to the same PEM bundle**. Mount
its containing directory read-only into containd, not the replaceable file inode,
and have the operator replace the bundle atomically in that directory. Separate
certificate and key files are also accepted, but cannot guarantee atomic
rotation: a mismatched or unreadable replacement keeps the last-good pair in
memory. With no valid pair at start, HTTPS is disabled and the reason is logged;
containd never self-signs external paths. Changing source paths requires restart.

`GET /api/v1/system/tls` describes configured and bound files (both file fields
name `server.pem` in managed mode). Its always-present boolean `managed` uses
the upload policy's identity-mode predicate for the next-start configuration
and environment, not the bound listener; `false` means external read-only mode.
Do not infer mode from paths: explicitly selecting `server.pem` as both source
paths is external mode even at `/data/tls/server.pem`.
Served certificate metadata, SSH/console
pins and the local CLI runtime record use the listener's validated public-leaf
snapshot, not an independently read certificate. `reloadError` reports an invalid
rotation while the last-good identity remains served. Private keys are never
returned. A pin/rotation race fails verification; retry the operation rather than
disabling certificate verification.

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

After storing the bundle, management sends its content and revision
(`sha256:<hex>`, or `none` when cleared) to the engine; the engine never reads
management's file. Every successful upload returns `200` with the stored
`revision`. Status `updated` means the engine applied it. Status `stored` means
the engine is unavailable or rejected it: the bundle stays stored, `warnings`
and the `X-Containd-Warnings` header say why, and every commit, rollback, boot
replay and `SIGHUP` reload sends it again. `503` means the config store is
unavailable and nothing was stored.

The engine's antivirus clients trust the system roots plus this bundle:

- ICAP servers with `useTls` (from the next connection).
- FreshClam definition downloads (from the next run). The engine writes the
  system roots and the bundle to an engine-local file and passes it to the
  FreshClam process only, as `CURL_CA_BUNDLE`.

See [security limits](secure-by-design.md#additional-ca-bundle) for clients
that do not use it.

## API endpoints

See [API Reference](api-reference.md) for endpoints and the OpenAPI wire contract.
Configuration lifecycle and JSON examples are maintained on this page.

## Runtime connections

The Sessions page and `GET /api/v1/conntrack` show the kernel's IPv4 and IPv6
connections, including original and reply NAT tuples. A successful empty array
is a verified empty table; unavailable or interrupted netlink dumps return an
error with the backend reason. The engine needs Linux conntrack support and
`NET_ADMIN` in the traffic's network namespace. The list is capped at 5,000 rows.

Admins use `POST /api/v1/conntrack/kill` with the displayed original tuple:
`proto`, `src`, `dst`, then `sport` and `dport` for TCP and UDP, or `icmpId`,
`icmpType` and `icmpCode` for ICMP (IPv4) and ICMPv6 (IPv6). ICMP connections
are queries such as pings: echo requests are type 8 (ICMP) and 128 (ICMPv6).
`scope: connection` (default) revokes only that exact connection in both
directions; reconnecting from a fresh source port, or pinging with a new ICMP
identifier, is allowed. `scope: client-service` ends all that client's
connections to the original destination service and prevents reconnects for the
interval. For ICMP the service is the query type and code sent to that
destination, so client-service ends all of the client's pings to that host.
Neighbouring clients, services and transports remain unaffected, and ICMP
errors about other connections, such as destination unreachable, still pass.
`durationSecs` is 1–3600 seconds, default 60. These are runtime operations, not
candidate configuration changes, and require active nftables enforcement.
Revocations never refuse management traffic: the management listeners stay
reachable on the interfaces that grant management access, and the reserved
management listener stays reachable, even when their tuples are revoked.
Killing a management connection still deletes its kernel state, which can end
that one connection.

The response reports `revocationInstalled`, `blockedUntil`, `conntrackDeleted`
and counts/errors independently. Revocation is installed atomically before
state deletion. Matching TCP packets receive kernel-generated resets on each
endpoint's next packet; this is not confirmed endpoint closure. Matching UDP,
ICMP and ICMPv6 packets are dropped, including echo requests and replies
without connection state: ICMP that an operator `notrack` rule exempts from
connection tracking, and replies that arrive after the connection's state was
deleted. A failed revocation does not delete kernel state. Inspect each step
even on HTTP 200. Other protocols are visible but cannot be killed.

Revocations are kernel runtime state in the nftables table
`inet <enforceTable>`, not persisted configuration. They survive commits
and expire after their interval. Disabling enforcement or renaming
`enforceTable` removes them, and a recreated container starts without them.
