import { expect, test } from "@playwright/test";

import { formatEndpoint } from "../lib/endpoint";

// Event and flow endpoints print a port only when there is one: ICMP and
// ICMPv6 events carry addresses with port 0. An IPv6 address with a port is
// bracketed.

test("formatEndpoint drops a zero port and brackets IPv6 with a port", () => {
  expect(formatEndpoint("192.0.2.1", 502)).toBe("192.0.2.1:502");
  expect(formatEndpoint("192.0.2.1", 0)).toBe("192.0.2.1");
  expect(formatEndpoint("192.0.2.1", undefined)).toBe("192.0.2.1");
  expect(formatEndpoint("2001:db8::1", 2404)).toBe("[2001:db8::1]:2404");
  expect(formatEndpoint("2001:db8::1", 0)).toBe("2001:db8::1");
  expect(formatEndpoint(undefined, 502)).toBe("—");
});

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
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const body = path.endsWith("/auth/me") || path.endsWith("/auth/session")
      ? { id: "admin", username: "containd", role: "admin" }
      : path === "/api/v1/events" ? { events, historyTruncated: false }
        : path.endsWith("/config/diff") ? { changed: false, changedSections: [] } : {};
    await route.fulfill({ json: body });
  });
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/events");
  await page.goto("/events/");
  await loaded;
  await expect(page.getByText("192.0.2.10 → 192.0.2.20 (icmp)", { exact: true })).toBeVisible();
  await expect(page.getByText("2001:db8::10 → 2001:db8::20 (icmpv6)", { exact: true })).toBeVisible();
  await expect(page.getByText("[2001:db8::10]:51000 → [2001:db8::20]:2404 (tcp)", { exact: true })).toBeVisible();
  expect(errors).toEqual([]);
});
