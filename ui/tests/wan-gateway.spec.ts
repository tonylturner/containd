import { expect, test, type Page } from "@playwright/test";

import type { InterfaceState, RoutingConfig } from "../lib/api";
import { guessGatewayAddress, inferWanGateway, pickWanCIDR, wanGateway, withDefaultRoute } from "../lib/wan-gateway";

// The routing page's Auto WAN setup and the firewall quick start both infer
// the WAN gateway from the WAN interface's runtime IPv4 address. They read
// only addresses that isCIDR and isIPv4 accept, so a malformed address never
// turns into a gateway, and they stage the same gateway and default route.

const state = (addrs: string[], name = "eth1"): InterfaceState => ({ name, index: 2, up: true, mtu: 1500, mac: "02:00:00:00:00:01", addrs });

test("guessGatewayAddress returns the address after the network address", () => {
  expect(guessGatewayAddress("192.0.2.7/24")).toBe("192.0.2.1");
  expect(guessGatewayAddress("10.20.30.40/8")).toBe("10.0.0.1");
  expect(guessGatewayAddress("172.16.5.9/0")).toBe("0.0.0.1");
  expect(guessGatewayAddress("198.51.100.6/30")).toBe("198.51.100.5");
  expect(guessGatewayAddress("255.255.255.254/30")).toBe("255.255.255.253");
});

test("guessGatewayAddress takes the other address of a /31 and refuses a /32", () => {
  expect(guessGatewayAddress("198.51.100.6/31")).toBe("198.51.100.7");
  expect(guessGatewayAddress("198.51.100.7/31")).toBe("198.51.100.6");
  expect(guessGatewayAddress("255.255.255.255/31")).toBe("255.255.255.254");
  expect(guessGatewayAddress("0.0.0.0/31")).toBe("0.0.0.1");
  expect(guessGatewayAddress("198.51.100.7/32")).toBeNull();
  expect(guessGatewayAddress("255.255.255.255/32")).toBeNull();
});

test("guessGatewayAddress refuses a first host that is the interface's own address", () => {
  expect(guessGatewayAddress("192.0.2.1/24")).toBeNull();
  expect(guessGatewayAddress("198.51.100.5/30")).toBeNull();
});

test("guessGatewayAddress refuses what isCIDR or isIPv4 refuses", () => {
  for (const cidr of [
    "010.0.0.1/24",
    "0x1.0.0.1/24",
    "1e1.0.0.1/24",
    "1.2.3/24",
    "1.2.3.4.5/24",
    "1.2.3.4/",
    "1.2.3.4/024",
    "1.2.3.4/33",
    "1.2.3.4/ 24",
    " 1.2.3.4/24",
    "1.2.3.4",
    "2001:db8::1/64",
  ]) {
    expect(guessGatewayAddress(cidr), cidr).toBeNull();
  }
});

test("pickWanCIDR picks the first IPv4 CIDR that is not link-local", () => {
  expect(pickWanCIDR(state(["fe80::1/64", "169.254.3.4/16", "010.0.0.5/24", "192.0.2.7/24"]))).toBe("192.0.2.7/24");
  expect(pickWanCIDR(state(["1.2.3.4/", "2001:db8::1/64"]))).toBeNull();
  expect(pickWanCIDR(null)).toBeNull();
});

test("inferWanGateway reads the state of the device the WAN interface is bound to", () => {
  expect(inferWanGateway([{ name: "uplink", device: " eth1 ", zone: "WAN" }], [state(["192.0.2.2/24"], "uplink"), state(["198.51.100.9/24"])]))
    .toEqual({ ok: true, wan: { device: "eth1", cidr: "198.51.100.9/24", address: "198.51.100.1" } });
  expect(inferWanGateway([{ name: "wan", device: " " }], [state(["192.0.2.2/24"], "wan")]))
    .toEqual({ ok: true, wan: { device: "wan", cidr: "192.0.2.2/24", address: "192.0.2.1" } });
  expect(inferWanGateway([{ name: "lan", zone: "lan" }], [])).toEqual({
    ok: false, error: "Could not determine WAN interface (expected an interface named 'wan' or in zone 'wan').",
  });
  expect(inferWanGateway([{ name: "wan", device: "eth1" }], [state(["169.254.1.1/16"])])).toEqual({
    ok: false, error: expect.stringMatching(/^Could not determine WAN IPv4 address for 'eth1'\./),
  });
  expect(inferWanGateway([{ name: "wan", device: "eth1" }], [state(["192.0.2.2/32"])]))
    .toEqual({ ok: false, error: "Could not infer a WAN gateway from '192.0.2.2/32'." });
});

test("withDefaultRoute replaces the named gateway and the main default route only", () => {
  const routing: RoutingConfig = {
    gateways: [{ name: "lab", address: "10.0.0.1" }, { name: "wan-gw", address: "192.0.2.254", iface: "old" }],
    routes: [
      { dst: "10.1.0.0/16", gateway: "lab" },
      { dst: "0.0.0.0/0", gateway: "lab", table: 100 },
      { dst: " 0.0.0.0/0 ", gateway: "lab" },
    ],
    rules: [{ table: 100, src: "10.2.0.0/16" }],
  };
  expect(withDefaultRoute(routing, wanGateway({ device: "eth1", cidr: "192.0.2.7/24", address: "192.0.2.1" }))).toEqual({
    gateways: [
      { name: "lab", address: "10.0.0.1" },
      { name: "wan-gw", address: "192.0.2.1", iface: "eth1", description: "Auto (WAN) from OS address" },
    ],
    routes: [
      { dst: "10.1.0.0/16", gateway: "lab" },
      { dst: "0.0.0.0/0", gateway: "lab", table: 100 },
      { dst: "default", gateway: "wan-gw", iface: "eth1", table: 0 },
    ],
    rules: [{ table: 100, src: "10.2.0.0/16" }],
  });
  expect(withDefaultRoute(null, { name: "os-default-gw", address: "192.0.2.1", iface: "eth0" })).toEqual({
    gateways: [{ name: "os-default-gw", address: "192.0.2.1", iface: "eth0" }],
    routes: [{ dst: "default", gateway: "os-default-gw", iface: "eth0", table: 0 }],
    rules: [],
  });
});

const existingRouting: RoutingConfig = {
  gateways: [{ name: "lab", address: "10.0.0.1" }],
  routes: [{ dst: "10.1.0.0/16", gateway: "lab" }, { dst: "default", gateway: "lab" }],
  rules: [{ table: 100, src: "10.2.0.0/16" }],
};

const stagedRouting = (address: string): RoutingConfig => ({
  gateways: [
    { name: "lab", address: "10.0.0.1" },
    { name: "wan-gw", address, iface: "eth1", description: "Auto (WAN) from OS address" },
  ],
  routes: [{ dst: "10.1.0.0/16", gateway: "lab" }, { dst: "default", gateway: "wan-gw", iface: "eth1", table: 0 }],
  rules: [{ table: 100, src: "10.2.0.0/16" }],
});

/** Serves an admin session, a WAN interface on eth1 holding wanAddr, and records every write. */
async function serveWan(page: Page, wanAddr: string) {
  const writes: { path: string; body: unknown }[] = [];
  await page.addInitScript(() => localStorage.setItem("containd.auth.role", "admin"));
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname.replace("/api/v1", "");
    if (request.method() === "POST") {
      const body = request.postDataJSON();
      writes.push({ path, body });
      return route.fulfill({ json: body, headers: { "X-Containd-Revision": "0123456789abcdef.1", "X-Containd-Config": "staged" } });
    }
    const user = { id: "admin-1", username: "admin", role: "admin", mfaRequired: false };
    const bodies: Record<string, unknown> = {
      "/auth/me": user,
      "/auth/session": user,
      "/interfaces": [{ name: "wan", device: "eth1", zone: "wan" }],
      "/interfaces/state": [state(["fe80::1/64", wanAddr])],
      "/routing": existingRouting,
      "/routing/os": { routes: [] },
      "/firewall/rules": [],
      "/firewall/nat": { enabled: false, sourceZones: [] },
      "/zones": [],
      "/dataplane": { captureInterfaces: [], dpiMock: false },
      "/config/diff": { changed: false, running: {}, candidate: {} },
    };
    return route.fulfill({ json: bodies[path] ?? {}, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  return writes;
}

test("the routing page's Auto WAN setup stages the gateway inferred on the WAN device", async ({ page }) => {
  const writes = await serveWan(page, "198.51.100.7/31");
  await page.goto("/routing/");
  await page.getByRole("button", { name: "Auto WAN default", exact: true }).click();
  await expect(page.getByText(/Gateway and default route staged.*'wan-gw' \(198\.51\.100\.6 via eth1\)/)).toBeVisible();
  expect(writes).toEqual([{ path: "/routing", body: stagedRouting("198.51.100.6") }]);
});

test("the routing page's Auto WAN setup stages nothing for a /32 WAN address", async ({ page }) => {
  const writes = await serveWan(page, "198.51.100.6/32");
  await page.goto("/routing/");
  await page.getByRole("button", { name: "Auto WAN default", exact: true }).click();
  await expect(page.getByText("Could not infer a WAN gateway from '198.51.100.6/32'.", { exact: true })).toBeVisible();
  expect(writes).toEqual([]);
});

test("the firewall quick start stages the same gateway and default route as the routing page", async ({ page }) => {
  const writes = await serveWan(page, "198.51.100.7/31");
  await page.goto("/firewall/");
  await page.getByRole("button", { name: "Quick start (LAN→WAN)", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Continue", exact: true }).click();
  await expect(page.getByText(/Outbound quick start staged — commit to apply: default route via wan-gw/)).toBeVisible();
  expect(writes[0]).toEqual({ path: "/routing", body: stagedRouting("198.51.100.6") });
});

test("default-route setup preserves existing gateway metadata and route metrics", () => {
  const routing = {
    gateways: [{ name: "wan-gw", address: "192.0.2.254", alias: "Uplink", description: "Existing" }],
    routes: [{ dst: "default", gateway: "wan-gw", table: 0, metric: 99 }],
    rules: [{ table: 100, src: "192.0.2.0/24" }],
  };
  expect(withDefaultRoute(routing, { name: "wan-gw", address: "192.0.2.1", iface: "eth1" })).toEqual({
    ...routing,
    gateways: [{ ...routing.gateways[0], address: "192.0.2.1", iface: "eth1" }],
    routes: [{ ...routing.routes[0], iface: "eth1" }],
  });
});

test("firewall quick start sends nothing when its fresh routing read fails", async ({ page }) => {
  const writes = await serveWan(page, "192.0.2.2/24");
  await page.goto("/firewall/");
  const quickStart = page.getByRole("button", { name: "Quick start (LAN→WAN)", exact: true });
  await expect(quickStart).toBeEnabled();
  await page.route("**/api/v1/routing", (route) => route.request().method() === "GET"
    ? route.fulfill({ status: 503, json: { error: "unavailable" }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } }) : route.fallback());
  await quickStart.click();
  await page.getByRole("dialog").getByRole("button", { name: "Continue", exact: true }).click();
  await expect(page.getByText("Routing configuration unavailable; no quick-start changes were staged.", { exact: true })).toBeVisible();
  await expect(quickStart).toBeDisabled();
  expect(writes).toEqual([]);
});
