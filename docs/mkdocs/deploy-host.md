# Host Deployment

This document is rendered from `docs/mkdocs/`.

Outlines installation and systemd service setup for running `ngfw-engine` and `ngfw-mgmt` on a host. To be completed in future phases.

Container builds:
- Appliance Dockerfile: `Dockerfile.mgmt` at repo root (builds single image).
- Optional engine-only Dockerfile: `Dockerfile.engine` at repo root.
- Compose: `docker-compose.yml` at repo root for single-container appliance.
- The previous `deploy/` directory was removed; all packaging assets live at repo root.

Registry publishing (recommended workflow):
- Tag the appliance image to your registry: `docker tag containd/containd:dev ghcr.io/you/containd:dev`
- Push: `docker push ghcr.io/you/containd:dev`
- Consume elsewhere with a single image reference: `docker run --rm -p 8080:8080 ghcr.io/you/containd:dev`

Runtime notes:
- Configuration DB path defaults to `data/config.db` (override `NGFW_CONFIG_DB`).
- HTTP API on `NGFW_MGMT_ADDR` (default `:8080`) exposes `/api/v1/*` for config/syslog/etc.

## VPN

- **WireGuard** is the preferred remote access VPN (implemented via kernel interfaces in the engine).
- **OpenVPN** is supported for compatibility (supervised by mgmt when enabled).

### OpenVPN (managed client)

The preferred path is to configure OpenVPN as a **managed client** from the UI:

- Configure `services.vpn.openvpn.managed` (remote/port/proto + CA/cert/key PEM blocks).
- mgmt renders a safe foreground config under `/data/openvpn/managed/` and supervises `openvpn --config /data/openvpn/managed/openvpn.conf`.
- Exported configs are redacted (cert/key/password removed). Encryption-at-rest is phased.

### OpenVPN profiles (advanced import)

You can also import a foreground `.ovpn` profile (advanced):

- Upload a `.ovpn` from the UI (VPN page) to store it under `/data/openvpn/profiles/` and automatically set `services.vpn.openvpn.configPath` (managed config is cleared).
- The OpenVPN supervisor requires a **foreground** config (do not include the `daemon` directive).

### Docker note (TUN)

OpenVPN requires a `tun` device. In Docker environments, this is typically provided by mapping `/dev/net/tun` into the container.

### OpenVPN (managed server) (phased)

Managed server mode is in progress:

- Configure `services.vpn.openvpn.mode=server` and `services.vpn.openvpn.server` (listen port/proto + `tunnelCIDR`).
- mgmt renders a server config under `/data/openvpn/managed/server/` and generates a local PKI under `/data/openvpn/managed/server/pki/`.
- Client profiles can be generated and downloaded as inline `.ovpn` files (requires setting `openvpn.server.publicEndpoint`).
- Enabling the OpenVPN server automatically opens the listen port on the WAN zone (nftables input) so clients can connect.
