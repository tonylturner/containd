# Config Format

Canonical JSON configuration for export/import and persistent state.

## Schema

```jsonc
{
  "schema_version": "0.1.0",
  "version": "0.1.0",
  "description": "optional",
  "system": {
    "hostname": "containd",
    "mgmt": {
      "listenAddr": ":8080",
      "enableHTTP": true,
      "enableHTTPS": true,
      "httpListenAddr": ":8080",
      "httpsListenAddr": ":8443",
      "tlsCertFile": "/data/tls/server.crt",
      "tlsKeyFile": "/data/tls/server.key",
      "trustedCAFile": "/data/tls/trusted_ca.pem"
    },
    "ssh": {
      "listenAddr": ":2222",
      "authorizedKeysDir": "/data/ssh/authorized_keys.d",
      "allowPassword": false
    }
  },
  "zones": [
    { "name": "it", "description": "IT network" },
    { "name": "dmz", "description": "DMZ" }
  ],
  "interfaces": [
    {
      "name": "eth0",
      "zone": "it",
      "addresses": ["192.168.1.1/24"],
      "access": { "mgmt": true, "http": true, "https": true, "ssh": false }
    },
    {
      "name": "eth1",
      "zone": "dmz",
      "addresses": ["10.0.0.1/24"],
      "access": { "mgmt": false, "http": false, "https": false, "ssh": false }
    }
  ],
  "dataplane": {
    "captureInterfaces": ["eth0", "eth1"],
    "enforcement": false,
    "enforceTable": "containd",
    "dpiMock": false
  },
  "routing": {
    "staticRoutes": [
      {
        "dst": "203.0.113.0/24",
        "via": "192.168.1.254",
        "dev": "wan",
        "table": 254,
        "metric": 100
      }
    ],
    "policyRules": [
      {
        "priority": 10010,
        "src": "192.168.1.0/24",
        "table": 100
      }
    ]
  },
  "assets": [
    {
      "id": "plc-1",
      "name": "Boiler PLC",
      "type": "PLC",
      "zone": "ot",
      "ips": ["10.0.0.10"],
      "hostnames": ["plc1.lab.local"],
      "criticality": "HIGH",
      "tags": ["boiler", "line-1"]
    }
  ],
  "services": {
    "syslog": {
      "forwarders": [
        { "address": "192.0.2.10", "port": 514, "proto": "udp" }
      ]
    },
    "dns": {
      "enabled": true,
      "listenPort": 53,
      "upstreamServers": ["1.1.1.1", "8.8.8.8"],
      "cacheSizeMB": 64
    },
    "ntp": {
      "enabled": true,
      "servers": ["pool.ntp.org"],
      "intervalSeconds": 3600
    },
    "dhcp": {
      "enabled": false,
      "authoritative": true,
      "listenIfaces": ["lan2", "lan3"],
      "leaseSeconds": 3600,
      "router": "192.168.10.1",
      "dnsServers": ["192.168.10.1"],
      "domain": "lab.local",
      "pools": [
        { "iface": "lan2", "start": "192.168.10.100", "end": "192.168.10.200" }
      ]
    },
    "vpn": {
      "wireguard": {
        "enabled": false,
        "iface": "wg0",
        "listenPort": 51820,
        "addressCIDR": "10.6.0.1/24",
        "privateKey": "REDACTED",
        "peers": [
          {
            "name": "laptop",
            "publicKey": "BASE64",
            "allowedIPs": ["10.6.0.2/32"],
            "endpoint": "vpn.example.com:51820",
            "persistentKeepalive": 25
          }
        ]
      },
      "openvpn": {
        "enabled": false,
        "mode": "server"
      }
    }
  },
  "firewall": {
    "defaultAction": "ALLOW",
    "nat": {
      "enabled": true,
      "egressZone": "wan",
      "sourceZones": ["lan", "dmz"]
    },
    "rules": [
      {
        "id": "1",
        "description": "IT to DMZ",
        "sourceZones": ["it"],
        "destZones": ["dmz"],
        "sources": ["192.168.1.0/24"],
        "destinations": ["10.0.0.0/24"],
        "protocols": [{ "name": "tcp", "port": "80" }],
        "ics": {
          "protocol": "modbus",
          "functionCode": [3, 16],
          "unitId": 1,
          "addresses": ["0-100"],
          "readOnly": false,
          "writeOnly": false
        },
        "action": "ALLOW"
      }
    ]
  }
}
```

Notes:
- `zones` must be unique.
- `interfaces.zone` must reference an existing zone; addresses are CIDR strings.
- `interfaces.addressMode` supports `static` (explicit CIDRs) and `dhcp` (best-effort; Docker commonly preconfigures IPs without DHCP).
- `interfaces.type` supports `physical` (default), `bridge` (with `members`), and `vlan` (with `parent` + `vlanId`).
- `interfaces.access` controls whether mgmt/ssh is reachable on that interface (defaults to enabled when omitted; localhost is always allowed).
- `services.dhcp` configures the built-in DHCP server.
- `services.vpn.wireguard` configures WireGuard. `services.vpn.openvpn` supports managed client/server modes.
- `services.vpn.openvpn.server.tunnelCIDR` is the client address pool allocated by the OpenVPN server. WireGuard uses static peer `AllowedIPs` and `addressCIDR` for policy targeting.
- Config backups are stored under `data/config-backups/` and can be created redacted or full (admin-only for unredacted).
- `assets` must have unique `id` and `name`; `zone` must reference an existing zone if set; `ips` are IPv4/IPv6 strings; `type` and `criticality` are enumerated strings.
- `dataplane` controls runtime capture/enforcement; values are pushed to the engine on commit/rollback.
- `routing` configures kernel routing when applying running config:
  - `staticRoutes` are installed via netlink (Linux only today; IPv4 only).
  - `policyRules` are installed via netlink as basic policy-based routing (Linux only today; src/dst CIDR selection, `table` selection).
- `firewall.rules` must have unique `id`; action is `ALLOW` or `DENY`.
- `firewall.nat` enables simple source NAT (masquerade) for traffic forwarded from `sourceZones` out `egressZone`.
- `protocols.port` accepts single ports or ranges (`"443"` or `"1000-2000"`).
- Syslog forwarders require address and port; proto `udp` or `tcp` (defaults to udp if empty).

Limitations (current):
- Routing/PBR supports additive updates plus an explicit replace/reconcile mode; coverage for all tables and IPv6 is still expanding.
- NAT supports postrouting masquerade and DNAT/port-forwarding.

## API endpoints
- `GET /api/v1/config` – fetch current config (404 if none).
- `POST /api/v1/config` – replace config (validates).
- `POST /api/v1/config/validate` – validate JSON without saving.
- `GET /api/v1/config/export` – export current config.
- `POST /api/v1/config/import` – import+save config (validates).
- `GET/POST /api/v1/config/candidate` – fetch/save candidate config.
- `GET /api/v1/config/diff` – view running vs candidate.
- `POST /api/v1/config/commit` – promote candidate to running.
- `POST /api/v1/config/commit_confirmed` – promote candidate to running with auto-rollback unless confirmed.
- `POST /api/v1/config/confirm` – confirm the last commit-confirmed operation.
- `POST /api/v1/config/rollback` – restore previous running config.
- `GET/POST /api/v1/config/backups` – list/create config backups.
- `GET /api/v1/config/backups/:id` – download a config backup.
- `DELETE /api/v1/config/backups/:id` – delete a config backup.
- `GET/POST/PATCH/DELETE /api/v1/zones` – list/add/update/delete zones.
- `GET/POST/PATCH/DELETE /api/v1/interfaces` – list/add/update/delete interfaces.
- `GET/POST/PATCH/DELETE /api/v1/firewall/rules` – list/add/update/delete firewall rules.
- `GET/POST/PATCH/DELETE /api/v1/assets` – list/add/update/delete assets.
- `GET/POST /api/v1/services/syslog` – get/set syslog settings.
- `GET/POST /api/v1/services/dns` – get/set DNS (Unbound) settings.
- `GET/POST /api/v1/services/ntp` – get/set NTP (OpenNTPD) settings.
- `GET/POST /api/v1/services/dhcp` – get/set DHCP (LAN) settings.
- `GET/POST /api/v1/services/vpn` – get/set VPN settings (WireGuard + OpenVPN managed client/server).
- `POST /api/v1/services/vpn/openvpn/profile` – upload a foreground `.ovpn` profile.
- `GET/POST /api/v1/services/vpn/openvpn/clients` – list/create OpenVPN server clients.
- `GET /api/v1/services/vpn/openvpn/clients/:name` – download a generated client profile.
- `GET/POST /api/v1/services/proxy/forward` – get/set forward proxy (Envoy).
- `GET/POST /api/v1/services/proxy/reverse` – get/set reverse proxy (Nginx).
- `GET/POST /api/v1/services/av` – get/set AV settings.
- `POST /api/v1/services/av/update` – trigger AV definition refresh.
- `GET/POST/DELETE /api/v1/services/av/defs` – manage AV definitions.
- `GET /api/v1/services/status` – summary of embedded service status.
- `GET /api/v1/audit` – list audit records.
- `GET /api/v1/events` – list DPI/firewall/service events.
- `GET /api/v1/flows` – list active flows.
- `GET /api/v1/stats/protocols` – protocol traffic statistics.
- `GET /api/v1/stats/top-talkers` – top source/destination pairs by volume.
- `GET /api/v1/anomalies` – list detected anomalies.
- `DELETE /api/v1/anomalies` – clear anomaly records (admin).
- `GET /api/v1/conntrack` – list kernel conntrack entries.
- `POST /api/v1/conntrack/kill` – kill a conntrack session (admin).
- `GET /api/v1/dataplane` – get dataplane config/status.
- `POST /api/v1/dataplane` – set dataplane config (admin).
- `GET /api/v1/dataplane/ruleset` – preview compiled ruleset (admin).
- `POST /api/v1/dataplane/blocks/host` – block a host (admin).
- `POST /api/v1/dataplane/blocks/flow` – block a flow (admin).
- `GET /api/v1/pcap/config` – get PCAP capture config.
- `POST /api/v1/pcap/config` – set PCAP capture config (admin).
- `POST /api/v1/pcap/start` – start PCAP capture (admin).
- `POST /api/v1/pcap/stop` – stop PCAP capture (admin).
- `GET /api/v1/pcap/status` – get PCAP capture status.
- `GET /api/v1/pcap/list` – list captured PCAP files.
- `POST /api/v1/pcap/upload` – upload a PCAP file (admin).
- `GET /api/v1/pcap/download/:name` – download a PCAP file.
- `DELETE /api/v1/pcap/:name` – delete a PCAP file (admin).
- `POST /api/v1/pcap/tag` – tag a PCAP file (admin).
- `POST /api/v1/pcap/replay` – replay a PCAP file through DPI (admin).
- `POST /api/v1/pcap/analyze` – upload and analyze a PCAP file (admin).
- `POST /api/v1/pcap/analyze/:name` – analyze a previously uploaded PCAP (admin).
- `GET /api/v1/inventory` – list auto-discovered ICS assets.
- `GET /api/v1/inventory/:ip` – get a specific discovered asset.
- `DELETE /api/v1/inventory` – clear discovered inventory (admin).
- `GET /api/v1/signatures` – list IDS signatures.
- `POST /api/v1/signatures` – add a custom signature (admin).
- `DELETE /api/v1/signatures/:id` – remove a signature (admin).
- `GET /api/v1/signatures/matches` – list signature match events.
- `GET /api/v1/objects` – list reusable objects (address groups, service groups).
- `POST /api/v1/objects` – create a reusable object (admin).
- `PATCH /api/v1/objects/:id` – update a reusable object (admin).
- `DELETE /api/v1/objects/:id` – delete a reusable object (admin).
- `POST /api/v1/firewall/rules/preview` – preview/test a firewall rule match (admin).
- `GET /api/v1/firewall/ics-rules` – list ICS-specific firewall rules.
- `POST /api/v1/firewall/ics-rules` – create an ICS firewall rule (admin).
- `PATCH /api/v1/firewall/ics-rules/:id` – update an ICS firewall rule (admin).
- `GET /api/v1/learn/profiles` – list learned traffic profiles.
- `POST /api/v1/learn/generate` – generate rules from learned profiles (admin).
- `POST /api/v1/learn/apply` – apply generated rules to config (admin).
- `DELETE /api/v1/learn` – clear learned profiles (admin).
- `GET /api/v1/ids/rules` – get IDS rules.
- `POST /api/v1/ids/rules` – set IDS rules (admin).
- `POST /api/v1/ids/convert/sigma` – convert Sigma YAML to containd IDS format.
- `GET /api/v1/templates` – list policy templates.
- `POST /api/v1/templates/apply` – apply a policy template (admin).
- `GET /api/v1/templates/ics` – list ICS protocol templates.
- `POST /api/v1/templates/ics/apply` – apply an ICS template (admin).
- `GET /api/v1/identities` – list identity mappings (when identity resolver is enabled).
- `POST /api/v1/identities` – set an identity mapping (admin).
- `DELETE /api/v1/identities/:ip` – delete an identity mapping (admin).
- `GET /api/v1/users` – list users (admin).
- `POST /api/v1/users` – create a user (admin).
- `PATCH /api/v1/users/:id` – update a user (admin).
- `POST /api/v1/users/:id/password` – set user password (admin).
- `DELETE /api/v1/users/:id` – delete a user (admin).
- `GET /metrics` – Prometheus metrics (unauthenticated).
