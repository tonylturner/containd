# Config Format

This document is rendered from `docs/mkdocs/`.

Canonical JSON configuration for export/import and persistent state.

## Schema (initial)

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
- `services.dhcp` configures the built-in DHCP server (phased; config-first).
- `services.vpn.wireguard` configures WireGuard (phased; config-first). `services.vpn.openvpn` is a placeholder.
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
- Routing/PBR is applied as “additive” changes; full reconcile/replace semantics are still in progress.
- NAT is currently postrouting masquerade only (no DNAT/port-forward yet).

## API endpoints (initial)
- `GET /api/v1/config` – fetch current config (404 if none).
- `POST /api/v1/config` – replace config (validates).
- `POST /api/v1/config/validate` – validate JSON without saving.
- `GET /api/v1/config/export` – export current config.
- `POST /api/v1/config/import` – import+save config (validates).
- `GET/POST /api/v1/config/candidate` – fetch/save candidate config.
- `GET /api/v1/config/diff` – view running vs candidate.
- `POST /api/v1/config/commit` – promote candidate to running.
- `POST /api/v1/config/rollback` – restore previous running config.
- `GET/POST/PATCH/DELETE /api/v1/zones` – list/add/update/delete zones.
- `GET/POST/PATCH/DELETE /api/v1/interfaces` – list/add/update/delete interfaces.
- `GET/POST/PATCH/DELETE /api/v1/firewall/rules` – list/add/update/delete firewall rules.
- `GET/POST/PATCH/DELETE /api/v1/assets` – list/add/update/delete assets.
- `GET/POST /api/v1/services/syslog` – get/set syslog settings.
- `GET/POST /api/v1/services/dns` – get/set DNS (Unbound) settings.
- `GET/POST /api/v1/services/ntp` – get/set NTP (OpenNTPD) settings.
- `GET/POST /api/v1/services/dhcp` – get/set DHCP (LAN) settings.
- `GET/POST /api/v1/services/vpn` – get/set VPN settings (WireGuard + OpenVPN placeholder).
- `GET/POST /api/v1/services/proxy/forward` – get/set forward proxy (Envoy).
- `GET/POST /api/v1/services/proxy/reverse` – get/set reverse proxy (Nginx).
- `GET /api/v1/services/status` – summary of embedded service status.
- `GET /api/v1/audit` – list audit records (write events pending).
