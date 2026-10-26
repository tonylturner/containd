import { expect, test } from "@playwright/test";

import { buildTopologyRules } from "../app/topology/topology-shared";
import type { FirewallRule } from "../lib/api";

// The firewall node lists the running rules: ALLOW admits, DENY and RESET
// refuse, RATE_LIMIT and TAG are effects. Hits come from the applied
// ruleset's counters and are unknown without them.

const rules: FirewallRule[] = [
  { id: "allow-hmi", action: "ALLOW", sourceZones: ["it"], destZones: ["ot"], protocols: [{ name: "tcp", port: "502" }] },
  { id: "reset-telnet", action: "RESET", protocols: [{ name: "tcp", port: "23" }] },
  { id: "deny-out", action: "DENY", sourceZones: ["ot"] },
  { id: "cap-dnp3", action: "RATE_LIMIT", rateLimit: { packetsPerSecond: 200, burst: 50 } },
  { id: "label-vendor", action: "TAG", tag: "vendor" },
];
const counters = {
  snapshotVersion: "v1",
  since: "2026-10-26T06:00:00Z",
  rules: [
    { ruleId: "allow-hmi", action: "ALLOW" as const, packets: 1500, bytes: 90000 },
    { ruleId: "reset-telnet", action: "RESET" as const, packets: 3, bytes: 180 },
    { ruleId: "cap-dnp3", action: "RATE_LIMIT" as const, packets: 40, bytes: 2400, excessDrops: 7 },
    { ruleId: "label-vendor", action: "TAG" as const, packets: 2, bytes: 120 },
  ],
};

test("topology rules keep their action, kind and counters", () => {
  const built = buildTopologyRules(rules, { ok: true, data: counters });
  expect(built.map((r) => [r.id, r.action, r.kind, r.hits])).toEqual([
    ["allow-hmi", "ALLOW", "allow", 1500],
    ["reset-telnet", "RESET", "deny", 3],
    ["deny-out", "DENY", "deny", null],
    ["cap-dnp3", "RATE_LIMIT", "effect", 40],
    ["label-vendor", "TAG", "effect", 2],
  ]);
  expect(built[0].desc).toBe("it → ot tcp/502");
  expect(built[3].desc).toBe("* → * · 200 pps, burst 50");
  expect(built[4].desc).toBe("* → * · tag vendor");
  const unavailable = buildTopologyRules(rules, { ok: false, error: "enforcement is off" });
  expect(unavailable.every((r) => r.hits === null)).toBe(true);
});

test("the firewall node shows effects apart from deny and real hit counts", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (err) => errors.push(String(err)));
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const data: Record<string, unknown> = {
      "/api/v1/auth/me": { id: "admin", username: "containd", role: "admin" },
      "/api/v1/auth/session": { id: "admin", username: "containd", role: "admin" },
      "/api/v1/config": {
        zones: [{ name: "it" }, { name: "ot" }],
        interfaces: [{ name: "lan1", device: "eth0", zone: "it", addresses: ["192.0.2.1/24"] }],
        routing: { gateways: [], routes: [], rules: [] },
        firewall: { rules },
      },
      "/api/v1/config/diff": { changed: false, changedSections: [] },
      "/api/v1/interfaces/state": [],
      "/api/v1/flows": [],
      "/api/v1/events": [],
      "/api/v1/firewall/counters": counters,
    };
    await route.fulfill({ json: data[path] ?? {} });
  });
  await page.goto("/topology/");
  await page.locator('.react-flow__node[data-id="fw-main"]').click();
  const rule = (id: string) => page.getByLabel(`Rule ${id}`);
  await expect(rule("allow-hmi")).toContainText("ALLOW");
  await expect(rule("allow-hmi")).toContainText("1,500");
  await expect(rule("allow-hmi")).toHaveClass(/ruleAllow/);
  await expect(rule("reset-telnet")).toHaveClass(/ruleDeny/);
  await expect(rule("cap-dnp3")).toHaveClass(/ruleEffect/);
  await expect(rule("cap-dnp3")).toContainText("RATE_LIMIT");
  await expect(rule("label-vendor")).toHaveClass(/ruleEffect/);
  await expect(rule("deny-out")).toContainText("—");
  expect(errors).toEqual([]);
});

test("topology reads health from the shared poll, not its own snapshot fetches", async ({ page }) => {
  let healthRequests = 0;
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/health") healthRequests++;
    const data: Record<string, unknown> = {
      "/api/v1/auth/me": { id: "admin", username: "containd", role: "admin" },
      "/api/v1/auth/session": { id: "admin", username: "containd", role: "admin" },
      "/api/v1/health": { status: "ok", component: "fw-lab-7", build: "9.9.9", time: new Date(Date.now() - 3 * 3600_000).toISOString() },
      "/api/v1/config": {
        zones: [{ name: "it" }],
        interfaces: [{ name: "lan1", device: "eth0", zone: "it", addresses: ["192.0.2.1/24"] }],
        routing: { gateways: [], routes: [], rules: [] },
        firewall: { rules: [] },
      },
      "/api/v1/config/diff": { changed: false, changedSections: [] },
      "/api/v1/interfaces/state": [],
      "/api/v1/flows": [],
      "/api/v1/events": [],
    };
    await route.fulfill({ json: data[path] ?? {} });
  });
  await page.goto("/topology/");
  await page.locator('.react-flow__node[data-id="fw-main"]').click();
  // Without system stats, uptime falls back to the time health reports.
  await expect(page.getByText("fw-lab-7", { exact: true })).toBeVisible();
  await expect(page.getByText("9.9.9", { exact: true })).toBeVisible();
  await expect(page.getByText(/^0d 3h \d+m$/)).toBeVisible();
  const afterLogical = healthRequests;
  await page.getByRole("button", { name: "PHYSICAL", exact: true }).click();
  await expect(page.getByText("9.9.9").first()).toBeVisible();
  // Loading the physical snapshot adds no health fetch.
  expect(healthRequests).toBe(afterLogical);
});
