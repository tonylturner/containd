# Customizing Lab Compose

This guide is for adapting `deploy/docker-compose.yml` to your own classroom, demo, or research lab topology.

Use Docker Compose to define the world of possible networks and interface attachments. Use containd to bind those interfaces to zones, apply policy, and enforce segmentation between workloads that route through the appliance.

## Design Rules

- Attach `containd` to every zone network you want it to filter.
- Keep normal workloads single-homed to one zone network whenever possible.
- Avoid attaching the same workload directly to multiple security zones unless you intentionally want a bypass path.
- Treat Docker as the owner of network existence, subnets, interface names, and container attachment.
- Treat containd as the owner of zone binding, firewall policy, NAT, DPI, and service configuration inside that Docker-defined topology.

## Start from the Starter Compose

The supported base file is `deploy/docker-compose.yml`. Copy it plus `.env.example` into a lab-specific directory and edit the `.env` values there.

If you want the project to do that setup for you, use:

```bash
curl -fsSLO https://raw.githubusercontent.com/tonylturner/containd/main/scripts/bootstrap-starter.sh
sh bootstrap-starter.sh --dir my-lab --no-start
```

That writes `docker-compose.yml`, `.env.example`, and `.env` into `my-lab/`, generates a real `CONTAIND_JWT_SECRET`, auto-adjusts conflicting default starter subnets on fresh setup, and leaves the directory ready for lab-specific edits before `docker compose up -d`.

Remember that `.env` and compose defaults seed a fresh appliance. If you keep the same `./data` directory between lab runs, the persisted containd config remains authoritative until you update it in the UI/API or remove that data directory.

The starter compose already does the important appliance wiring:

- combined `containd all` mode
- management plane auto-wired to the local engine
- nftables enforcement enabled by default
- `user: "0"` so nftables, routing, and TUN operations work across Linux, Docker Desktop, and WSL-backed labs
- stable `wan`/`dmz`/`lan1`-`lan6` network to `eth0`-`eth7` mapping
- Docker `internal` networks for the non-WAN zones

## Customizations That Usually Belong in `.env`

Use `.env` when you only need to change addressing or published ports:

- `CONTAIND_WAN_SUBNET`, `CONTAIND_DMZ_SUBNET`, `CONTAIND_LAN1_SUBNET` ... `CONTAIND_LAN6_SUBNET`
- `CONTAIND_WAN_IP`, `CONTAIND_DMZ_IP`, `CONTAIND_LAN1_IP` ... `CONTAIND_LAN6_IP`
- `CONTAIND_PUBLISH_HTTP_PORT`, `CONTAIND_PUBLISH_HTTPS_PORT`, `CONTAIND_PUBLISH_SSH_PORT`
- `CONTAIND_JWT_SECRET`

If you change the starter subnets, keep the auto-assign hints aligned too:

- `CONTAIND_AUTO_WAN_SUBNET`
- `CONTAIND_AUTO_DMZ_SUBNET`
- `CONTAIND_AUTO_LAN1_SUBNET` ... `CONTAIND_AUTO_LAN6_SUBNET`

## Customizations That Belong in `docker-compose.yml`

Edit the compose file when you need to change the lab topology itself:

- add or remove zone networks
- rename zone networks
- add workload containers
- add an optional control-plane-only management network
- attach `containd` to more or fewer zone networks

## Example: Add a New Zone

To add a new `ot-control` zone:

1. Add a new network under `services.containd.networks`
2. Pin its `interface_name`
3. Add the matching top-level network definition
4. Add matching subnet/IP variables to your `.env`
5. Add the matching `CONTAIND_AUTO_*_SUBNET` hint if you want auto-assign to stay deterministic

Example service/network snippet:

```yaml
services:
  containd:
    networks:
      ot_control:
        ipv4_address: ${CONTAIND_OT_CONTROL_IP:-192.168.248.2}
        gw_priority: 0
        priority: 200
        interface_name: eth8

networks:
  ot_control:
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: ${CONTAIND_OT_CONTROL_SUBNET:-192.168.248.0/24}
```

## Example: Add Student Workloads

Attach each lab workload to exactly one zone network unless it is intentionally acting as a relay or shared service.

Example:

```yaml
services:
  historian:
    image: ghcr.io/example/historian:latest
    networks:
      dmz:
        ipv4_address: 192.168.241.20

  plc:
    image: ghcr.io/example/plc:latest
    networks:
      lan1:
        ipv4_address: 192.168.242.20
```

With that layout, traffic between `historian` and `plc` only crosses zones through containd.

## Optional Management Network

If you want a separate orchestration path that is not part of the segmentation exercise, add a dedicated `mgmt_net` and attach only the components that need it.

Keep it clearly out-of-band:

- use it for SSH, automation, or instructor tooling
- do not present it as a student security zone
- do not expect containd policy to filter traffic that never routes through the appliance

## Dockerfile Changes Are Usually Not Needed

You normally do not need to edit the Dockerfile to customize a lab.

Use compose changes when you need:

- different networks
- more or fewer interfaces
- different images for workloads
- different ports, capabilities, or mounted volumes

Only rebuild the containd image when you are changing containd itself:

- code changes
- packaged binaries
- bundled UI/docs
- base image or dependency updates

## Platform Notes

- Linux Docker hosts are supported targets for full container-lab segmentation.
- Docker Desktop on macOS is also a valid target because the filtered traffic lives inside Docker's Linux VM.
- Docker Desktop on Windows should use the WSL2 backend.
- containd is not a native host firewall for macOS or Windows networking.

## Validation Checklist

After customizing a lab compose:

- `docker compose config -q`
- `docker compose up -d`
- confirm `Interfaces -> Auto-assign` maps the expected interfaces
- bind interfaces to zones and commit config
- verify cross-zone traffic succeeds only when policy allows it
- verify unwanted direct multi-homing or alternate Docker paths are not bypassing containd
