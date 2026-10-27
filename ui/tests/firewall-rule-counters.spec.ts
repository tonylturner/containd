import { expect, test, type Page } from "@playwright/test";

import { normalizeRuleCounters } from "../lib/api-firewall";

// GET /firewall/counters reports the applied ruleset's per-rule counters.
// Without an applied ruleset it fails with the reason; the rule list stays
// usable and says so quietly.

const user = { id: "admin-1", username: "containd", role: "admin", mfaRequired: false };
const rules = [
  { id: "allow-hmi", action: "ALLOW", protocols: [{ name: "tcp", port: "502" }] },
  { id: "pps-cap", action: "RATE_LIMIT", rateLimit: { packetsPerSecond: 100 } },
  { id: "label-eng", action: "TAG", tag: "eng" },
  { id: "staged-only", action: "DENY" },
];
const since = "2026-10-26T08:00:00Z";
const counters = {
  snapshotVersion: "abc123",
  since,
  rules: [
    { ruleId: "allow-hmi", action: "ALLOW", packets: 123456, bytes: 7340032 },
    { ruleId: "pps-cap", action: "RATE_LIMIT", packets: 900, bytes: 54000, excessDrops: 42 },
    { ruleId: "label-eng", action: "TAG", packets: 7, bytes: 420 },
  ],
};

async function openFirewall(page: Page, response: { status: number; json: unknown }) {
  const errors: string[] = [];
  page.on("pageerror", (err) => errors.push(String(err)));
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/firewall/counters") {
      await route.fulfill(response);
      return;
    }
    let body: unknown = {};
    if (path === "/api/v1/auth/me" || path === "/api/v1/auth/session") body = user;
    if (path === "/api/v1/firewall/rules") body = rules;
    if (path === "/api/v1/zones") body = [];
    if (path === "/api/v1/routing") body = { gateways: [], routes: [], rules: [] };
    if (path === "/api/v1/dataplane") body = { captureInterfaces: [], dpiMock: false };
    await route.fulfill({ json: body });
  });
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/firewall/counters");
  await page.goto("/firewall/");
  await loaded;
  return errors;
}

test("the rule list shows hits, excess drops and when counting started", async ({ page }) => {
  const errors = await openFirewall(page, { status: 200, json: counters });
  const sinceText = await page.evaluate((s) => new Date(s).toLocaleString(), since);
  await expect(page.getByRole("status", { name: "Rule counters" })).toContainText(`Hit counters since ${sinceText}`);
  await expect(page.getByRole("status", { name: "Rule counters" })).toContainText("every apply restarts them at zero");

  const hits = (id: string) => page.getByLabel(`Hits of ${id}`);
  const count = (n: number) => page.evaluate((v) => v.toLocaleString(), n);
  await expect(hits("allow-hmi")).toContainText(`${await count(123456)} pkts`);
  await expect(hits("allow-hmi")).toContainText("7.0 MB");
  await expect(hits("pps-cap")).toContainText("42 over limit");
  await expect(hits("pps-cap").getByText("42 over limit")).toHaveClass(/text-amber/);
  await expect(hits("label-eng")).toContainText("7 conns");
  await expect(hits("label-eng")).not.toContainText("over limit");
  await expect(page.getByRole("row").filter({ hasText: "staged-only" })).toContainText("not applied");
  expect(errors).toEqual([]);
});

for (const status of [502, 503]) {
  test(`unavailable counters (${status}) are a quiet state, not an error`, async ({ page }) => {
    const reason = "rule counters unavailable: nftables enforcement is not active";
    const errors = await openFirewall(page, { status, json: { error: reason } });
    const note = page.getByRole("status", { name: "Rule counters" });
    await expect(note).toHaveText(`Hit counters unavailable: ${reason}`);
    await expect(note).toHaveClass(/text-\(--text-dim\)/);
    await expect(page.getByRole("row").filter({ hasText: "allow-hmi" })).toBeVisible();
    await expect(page.getByLabel("Hits of allow-hmi")).toHaveCount(0);
    await expect(page.getByRole("alert").filter({ hasText: reason })).toHaveCount(0);
    await expect(page.locator(".bg-red-500\\/10")).toHaveCount(0);
    expect(errors).toEqual([]);
  });
}

test("counter responses are validated before use", () => {
  expect(normalizeRuleCounters(counters)?.rules).toHaveLength(3);
  expect(normalizeRuleCounters({})).toBeNull();
  expect(normalizeRuleCounters({ since, rules: {} })).toBeNull();
  expect(normalizeRuleCounters({ since, rules: [{ ruleId: "x", packets: "1", bytes: 2 }, { ruleId: "y", action: "TAG", packets: 1, bytes: 2 }] })).toEqual({
    snapshotVersion: "",
    since,
    rules: [{ ruleId: "y", action: "TAG", packets: 1, bytes: 2 }],
  });
});
