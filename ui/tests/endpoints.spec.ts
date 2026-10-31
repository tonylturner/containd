import { expect, test, type Page } from "@playwright/test";

import { formatEndpoint } from "../lib/endpoint";

// Event, flow, connection and forward endpoints print a port only when there
// is one: ICMP and ICMPv6 events carry addresses with port 0. An IPv6 address
// with a port is bracketed.

test("formatEndpoint drops a zero port and brackets IPv6 with a port", () => {
  expect(formatEndpoint("192.0.2.1", 502)).toBe("192.0.2.1:502");
  expect(formatEndpoint("192.0.2.1", 0)).toBe("192.0.2.1");
  expect(formatEndpoint("192.0.2.1", undefined)).toBe("192.0.2.1");
  expect(formatEndpoint("2001:db8::1", 2404)).toBe("[2001:db8::1]:2404");
  expect(formatEndpoint("2001:db8::1", 0)).toBe("2001:db8::1");
  expect(formatEndpoint(undefined, 502)).toBe("—");
});

test("formatEndpoint reads decimal string ports as conntrack and form inputs send them", () => {
  expect(formatEndpoint("2001:db8::1", "41001")).toBe("[2001:db8::1]:41001");
  expect(formatEndpoint("192.0.2.1", "0")).toBe("192.0.2.1");
  expect(formatEndpoint("192.0.2.1", "")).toBe("192.0.2.1");
  expect(formatEndpoint("", "443")).toBe("—");
});

// Serves the given bodies by API path, with an admin session and a clean
// config diff; any other path answers {}.
async function mockAPI(page: Page, bodies: Record<string, unknown>) {
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const body = path.endsWith("/auth/me") || path.endsWith("/auth/session")
      ? { id: "admin", username: "containd", role: "admin" }
      : path.endsWith("/config/diff") ? { changed: false, changedSections: [] } : bodies[path] ?? {};
    await route.fulfill({ json: body });
  });
}

async function open(page: Page, url: string, dataPath: string) {
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === dataPath);
  await page.goto(url);
  await loaded;
}

const events = [
  {
    id: 1, flowId: "icmp-flow", proto: "firewall", kind: "firewall.rule.hit", timestamp: "2026-10-26T08:00:00Z",
    srcIp: "192.0.2.10", dstIp: "192.0.2.20", transport: "icmp", attributes: { action: "DENY" },
  },
  {
    id: 2, flowId: "icmpv6-flow", proto: "firewall", kind: "firewall.rule.hit", timestamp: "2026-10-26T08:00:01Z",
    srcIp: "2001:db8::10", dstIp: "2001:db8::20", transport: "icmpv6", attributes: { action: "DENY" },
  },
  {
    id: 3, flowId: "tcp6-flow", proto: "firewall", kind: "firewall.rule.hit", timestamp: "2026-10-26T08:00:02Z",
    srcIp: "2001:db8::10", srcPort: 51000, dstIp: "2001:db8::20", dstPort: 2404, transport: "tcp", attributes: { action: "ALLOW" },
  },
];

test("the events page shows ICMP endpoints without ports", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (err) => errors.push(String(err)));
  await mockAPI(page, { "/api/v1/events": { events, historyTruncated: false } });
  await open(page, "/events/", "/api/v1/events");
  await expect(page.getByText("192.0.2.10 → 192.0.2.20 (icmp)", { exact: true })).toBeVisible();
  await expect(page.getByText("2001:db8::10 → 2001:db8::20 (icmpv6)", { exact: true })).toBeVisible();
  await expect(page.getByText("[2001:db8::10]:51000 → [2001:db8::20]:2404 (tcp)", { exact: true })).toBeVisible();
  expect(errors).toEqual([]);
});

test("the sessions page shows a portless ICMP reply tuple as addresses", async ({ page }) => {
  await mockAPI(page, {
    "/api/v1/conntrack": [{
      proto: "icmp", src: "192.0.2.10", dst: "192.0.2.20", replySrc: "192.0.2.20", replyDst: "192.0.2.10",
    }],
  });
  await open(page, "/sessions/", "/api/v1/conntrack");
  await expect(page.getByRole("cell", { name: "192.0.2.20 → 192.0.2.10", exact: true })).toBeVisible();
});

const zones = [{ name: "wan" }, { name: "lan" }];

test("the NAT page brackets an IPv6 port forward destination", async ({ page }) => {
  await mockAPI(page, {
    "/api/v1/zones": zones,
    "/api/v1/firewall/nat": {
      enabled: true,
      portForwards: [
        { id: "pf6", enabled: true, ingressZone: "wan", proto: "tcp", listenPort: 2404, destIp: "2001:db8::5", destPort: 2404 },
        { id: "pf4", enabled: true, ingressZone: "wan", proto: "tcp", listenPort: 8443, destIp: "192.0.2.5" },
      ],
    },
  });
  await open(page, "/nat/", "/api/v1/firewall/nat");
  await expect(page.getByRole("cell", { name: "[2001:db8::5]:2404", exact: true })).toBeVisible();
  await expect(page.getByRole("cell", { name: "192.0.2.5:8443", exact: true })).toBeVisible();
});
