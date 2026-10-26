/**
 * WAN default gateway inference for the routing page's Auto WAN setup and
 * the firewall's outbound quick start: find the WAN interface, read its
 * runtime IPv4 address, guess the gateway on that subnet, and stage it as a
 * gateway with a default route through it.
 */

import type { Gateway, Interface, InterfaceState, RoutingConfig, StaticRoute } from "./api";
import { isCIDR, isIPv4 } from "./validate";

/** Name of the gateway the WAN inference stages. */
export const WAN_GATEWAY_NAME = "wan-gw";

/** True if s is an IPv4 CIDR as isCIDR and isIPv4 read one (192.0.2.7/24). */
function isIPv4CIDR(s: string): boolean {
  return isCIDR(s) && isIPv4(s.slice(0, s.lastIndexOf("/")));
}

/** The address as an unsigned 32-bit number; ip must already pass isIPv4. */
function ip4ToInt(ip: string): number {
  return ip.split(".").reduce((n, octet) => ((n << 8) | Number(octet)) >>> 0, 0);
}

function intToIP4(n: number): string {
  const v = n >>> 0;
  return `${(v >>> 24) & 255}.${(v >>> 16) & 255}.${(v >>> 8) & 255}.${v & 255}`;
}

/**
 * The gateway guess for an interface that holds the IPv4 address cidr: the
 * first address after the network address. Null for anything that is not an
 * IPv4 CIDR.
 */
export function guessGatewayAddress(cidr: string): string | null {
  if (!isIPv4CIDR(cidr)) return null;
  const slash = cidr.lastIndexOf("/");
  const prefix = Number(cidr.slice(slash + 1));
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const net = (ip4ToInt(cidr.slice(0, slash)) & mask) >>> 0;
  return intToIP4(net + 1);
}

/** The interface named "wan", else the first one in zone "wan". */
export function pickWanIface(ifs: Interface[]): Interface | null {
  const byName = ifs.find((i) => i.name === "wan");
  if (byName) return byName;
  const byZone = ifs.find((i) => (i.zone || "").toLowerCase() === "wan");
  return byZone ?? null;
}

/** The first IPv4 CIDR of the interface state that is not link-local. */
export function pickWanCIDR(state: InterfaceState | null): string | null {
  if (!state) return null;
  for (const addr of state.addrs || []) {
    const s = String(addr);
    if (!isIPv4CIDR(s)) continue;
    if (s.startsWith("169.254.")) continue;
    return s;
  }
  return null;
}

/** The inferred WAN gateway on the OS device the WAN interface is bound to. */
export type WanGateway = { device: string; cidr: string; address: string };

/**
 * Infers the WAN gateway from the configured interfaces and their runtime
 * state, or explains why it cannot.
 */
export function inferWanGateway(
  ifs: Interface[],
  states: InterfaceState[],
): { ok: true; wan: WanGateway } | { ok: false; error: string } {
  const iface = pickWanIface(ifs);
  if (!iface) {
    return { ok: false, error: "Could not determine WAN interface (expected an interface named 'wan' or in zone 'wan')." };
  }
  const device = iface.device?.trim() || iface.name;
  const cidr = pickWanCIDR(states.find((s) => s.name === device) ?? null);
  if (!cidr) {
    return {
      ok: false,
      error: `Could not determine WAN IPv4 address for '${device}'. If you're using DHCP in Docker, restart the container so Docker assigns an IP at startup.`,
    };
  }
  const address = guessGatewayAddress(cidr);
  if (!address) return { ok: false, error: `Could not infer a WAN gateway from '${cidr}'.` };
  return { ok: true, wan: { device, cidr, address } };
}

/** The gateway the WAN inference stages for wan. */
export function wanGateway(wan: WanGateway): Gateway {
  return { name: WAN_GATEWAY_NAME, address: wan.address, iface: wan.device, description: "Auto (WAN) from OS address" };
}

function isDefaultDst(dst: string): boolean {
  const d = dst.trim().toLowerCase();
  return d === "default" || d === "0.0.0.0/0";
}

/**
 * The routing config with gateway added, or replacing the gateway of the
 * same name, and the main table's default route sent through it.
 */
export function withDefaultRoute(routing: RoutingConfig | null, gateway: Gateway): RoutingConfig {
  const gateways = routing?.gateways ?? [];
  const routes = routing?.routes ?? [];
  const gwIdx = gateways.findIndex((g) => g.name === gateway.name);
  const routeIdx = routes.findIndex((r) => isDefaultDst(r.dst) && (r.table ?? 0) === 0);
  const route: StaticRoute = { dst: "default", gateway: gateway.name, iface: gateway.iface, table: 0 };
  return {
    gateways: gwIdx >= 0 ? gateways.map((g, i) => (i === gwIdx ? gateway : g)) : [...gateways, gateway],
    routes: routeIdx >= 0 ? routes.map((r, i) => (i === routeIdx ? route : r)) : [...routes, route],
    rules: routing?.rules ?? [],
  };
}
