# Customizing Lab Compose

This guide uses the **training** profile. Lab mode and shell access are
training-only; see [deployment profiles](deployment-profiles.md) for strict.

This guide is for adapting `deploy/docker-compose.yml` to your own classroom, demo, or research lab topology.

Use Docker Compose to define the world of possible networks and interface attachments. Use containd to bind those interfaces to zones, apply policy, and enforce segmentation between workloads that route through the appliance.

## Design Rules

- Attach `containd` to every zone network you want it to filter.
- Keep normal workloads single-homed to one zone network whenever possible.
- Avoid attaching the same workload directly to multiple security zones unless you intentionally want a bypass path.
- Treat Docker as the owner of network existence, subnets, interface names, and container attachment.
- Treat containd as the owner of zone binding, firewall policy, NAT, DPI, and service configuration inside that Docker-defined topology.

## Start from the Starter Compose

Follow [Docker Compose onboarding](docker-compose.md#quickstart) to create a
starter directory with a generated JWT secret. Stop before first boot if you
need to change topology. That page also covers ports, runtime variables,
persistent-data locations, and the engine trust boundary: namespace-local HTTP
on numeric loopback or mutual TLS for non-loopback listeners.

The starter runs combined mode with enforcement enabled and root/capabilities
for network operations. Requires Docker Engine 28.1+ and Compose with
`interface_name` support (2.36.0+). Every appliance attachment is explicitly named
after its containd row; network attachment order is irrelevant. Non-WAN networks are Docker
`internal` networks. Config-seeding variables do not replace persisted policy;
make policy changes through the UI/API and commit.

## Customizations That Usually Belong in `.env`

Use `.env` when you only need to change addressing or published ports:

- `CONTAIND_WAN_SUBNET`, `CONTAIND_DMZ_SUBNET`, `CONTAIND_LAN1_SUBNET` ... `CONTAIND_LAN6_SUBNET`
- `CONTAIND_WAN_IP`, `CONTAIND_DMZ_IP`, `CONTAIND_LAN1_IP` ... `CONTAIND_LAN6_IP`
- `CONTAIND_PUBLISH_HTTP_PORT`, `CONTAIND_PUBLISH_HTTPS_PORT`, `CONTAIND_PUBLISH_SSH_PORT`
- `CONTAIND_JWT_SECRET`
- `CONTAIND_LAB_MODE` — set to `1` only for disposable workshop / classroom / single-host lab deployments. Disables password change so reproducible lab docs and SSH-on-`:2222` keep working across student runs. Existing and custom-seeded credentials are kept; a freshly seeded lab uses `containd/containd`. Lab API authentication bypasses session lookup, but signed tokens must carry `exp` and be unexpired; login does not extend the normal token lifetime. **This is a deliberate weakening of the default-password posture, scoped to the lab boundary.** Read the [Secure by Design § Default Passwords](secure-by-design.md#2-default-passwords) transparency note before enabling. Do NOT set this on any deployment whose HTTP UI or SSH port is reachable from a hostile or shared network.

Subnet variables configure Compose IPAM only; containd does not use them to
identify interfaces. See [interface mapping](docker-compose.md#logical-roles-and-kernel-devices).

Give each lab its own data folder. A bootstrapped starter uses `./data` beside
its compose; a separate lab should live in its own directory or mount a unique
folder such as `./data-ot-lab:/data`. The repository strict and dev manifests use
`deploy/data-strict/` and repository-root `data/` respectively. Strict accepts
`CONTAIND_DATA_DIR` for an alternative folder. Never share a folder across labs or profiles. Existing users
must follow the [data move steps](update-policy.md#existing-data-directories).

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
2. Set its `interface_name` to the intended interface row name (`ot-control`)
3. Add the matching top-level network definition
4. Add matching subnet/IP variables to your `.env`
5. Recreate the appliance, then create the `ot-control` zone and a physical row
   named exactly `ot-control` in containd
6. Verify that the row is attached, assign its zone, and commit

Example service/network snippet:

```yaml
services:
  containd:
    networks:
      ot_control:
        interface_name: ot-control
        ipv4_address: ${CONTAIND_OT_CONTROL_IP:-192.168.248.2}
        gw_priority: 0
        priority: 200

networks:
  ot_control:
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: ${CONTAIND_OT_CONTROL_SUBNET:-192.168.248.0/24}
```

Docker network creation does not create a containd zone or row. The Docker
network key (`ot_control`) may differ from its attachment's kernel name
(`ot-control`), but the containd row name must equal that kernel name. There is
no discovery or separate device binding to repair after network reattachment.

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

These images are illustrative, not runnable workload definitions. Network
attachment alone does not install the routes needed for cross-zone traffic.
Each workload needs `iproute2`, permission to change routes (`NET_ADMIN` during
setup), and a route via containd's address on its own network. For example, run
inside the respective workload network namespaces after attachment:

```sh
# historian (DMZ)
ip route replace 192.168.242.0/24 via 192.168.241.2
# plc (LAN1): return route
ip route replace 192.168.241.0/24 via 192.168.242.2
```

Use the actual addresses if you changed the subnets. Ensure containd has both
interfaces bound, forwarding/enforcement configured, and an allow rule for the
intended flow. Check both directions; do not rely on Docker's bridge gateway
for routed segmentation. With these prerequisites and no alternate path,
cross-zone traffic traverses containd.

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
- confirm each row in Interfaces is attached to its identically named device
- bind interfaces to zones and commit config
- verify cross-zone traffic succeeds only when policy allows it
- verify unwanted direct multi-homing or alternate Docker paths are not bypassing containd
