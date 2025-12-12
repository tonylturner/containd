# Config Format

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
    }
  },
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
- `interfaces.access` controls whether mgmt/ssh is reachable on that interface (defaults to enabled when omitted; localhost is always allowed).
- `assets` must have unique `id` and `name`; `zone` must reference an existing zone if set; `ips` are IPv4/IPv6 strings; `type` and `criticality` are enumerated strings.
- `dataplane` controls runtime capture/enforcement; values are pushed to the engine on commit/rollback.
- `firewall.rules` must have unique `id`; action is `ALLOW` or `DENY`.
- `protocols.port` accepts single ports or ranges (`"443"` or `"1000-2000"`).
- Syslog forwarders require address and port; proto `udp` or `tcp` (defaults to udp if empty).

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
- `GET/POST /api/v1/services/proxy/forward` – get/set forward proxy (Envoy).
- `GET/POST /api/v1/services/proxy/reverse` – get/set reverse proxy (Nginx).
- `GET /api/v1/services/status` – summary of embedded service status.
- `GET /api/v1/audit` – list audit records (write events pending).
