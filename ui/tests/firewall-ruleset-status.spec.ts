import { expect, test, type Page } from "@playwright/test";

import { normalizeEnforcementHealth } from "../lib/api-health";
import { formatStatusTime } from "../app/firewall/firewall-ruleset-status";

// Health's enforcement state is degraded while a ruleset is in force but the
// last apply failed or the schedule planner is degraded. The ruleset preview
// carries the installed ruleset's status: the failed apply and the planner.

const user = { id: "admin-1", username: "containd", role: "admin", mfaRequired: false };

async function mockAPI(page: Page, mocks: { enforcement?: unknown; engineStatus?: unknown }) {
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    let body: unknown = {};
    if (path === "/api/v1/auth/me" || path === "/api/v1/auth/session") body = user;
    if (path === "/api/v1/health") body = { status: "ok", component: "mgmt", enforcement: mocks.enforcement };
    if (path === "/api/v1/firewall/rules" || path === "/api/v1/zones") body = [];
    if (path === "/api/v1/routing") body = { gateways: [], routes: [], rules: [] };
    if (path === "/api/v1/dataplane") body = { captureInterfaces: [], dpiMock: false };
    if (path === "/api/v1/dataplane/ruleset") {
      body = { ruleset: "table inet containd_policy {}", runtime: { iec104EnvelopeOpen: false, reason: "no IEC 104 rules" }, engineStatus: mocks.engineStatus };
    }
    await route.fulfill({ json: body });
  });
}

async function open(page: Page, path: string) {
  const health = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/health");
  await page.goto(path);
  await health;
}

for (const path of ["/firewall/", "/ics/"]) {
  test(`${path} shows degraded enforcement in amber with its reason`, async ({ page }) => {
    await mockAPI(page, { enforcement: { state: "degraded", reason: "last ruleset apply failed; previous ruleset in force" } });
    await open(page, path);
    const indicator = page.getByRole("status", { name: "Firewall enforcement degraded: degraded" });
    await expect(indicator).toContainText("last ruleset apply failed; previous ruleset in force");
    await expect(indicator.locator("span[aria-hidden]")).toHaveClass(/bg-\(--amber\)/);
  });
}

for (const [state, label, status] of [
  ["enforcing", "Firewall enforcing", "healthy"],
  ["disabled", "Firewall enforcement disabled", "unknown"],
  ["unavailable", "Firewall enforcement unavailable", "error"],
] as const) {
  test(`enforcement ${state} is labelled`, async ({ page }) => {
    await mockAPI(page, { enforcement: { state, reason: "" } });
    await open(page, "/firewall/");
    await expect(page.getByRole("status", { name: `${label}: ${status}` })).toBeVisible();
  });
}

test("the ruleset preview shows a failed apply and a degraded schedule planner", async ({ page }) => {
  const failedAt = "2026-10-26T07:30:00Z";
  const horizonEnd = "2026-10-26T08:10:00Z";
  await mockAPI(page, {
    enforcement: { state: "degraded", reason: "schedule planner degraded" },
    engineStatus: {
      appliedAt: "2026-10-26T06:00:00Z", snapshotVersion: "v41",
      error: "nft: Error: Could not process rule", failedSnapshotVersion: "v42", failedAt,
      schedulePlanner: {
        lastRefill: "2026-10-25T08:10:00Z", horizonEnd, state: "degraded",
        reason: "the schedule horizon ends within an hour", lastError: "set refill: netlink busy", lastErrorAt: "2026-10-26T07:40:00Z",
      },
    },
  });
  await open(page, "/firewall/");
  await page.getByRole("button", { name: "Preview", exact: true }).click();
  const applied = page.getByRole("region", { name: "Applied ruleset" });
  await expect(applied).toContainText("snapshot v41");
  const failed = applied.getByRole("status", { name: "Failed apply" });
  const failedText = await page.evaluate((t) => new Date(t).toLocaleString(), failedAt);
  await expect(failed).toContainText(`Last apply failed at ${failedText} (snapshot v42)`);
  await expect(failed).toContainText("nft: Error: Could not process rule");
  await expect(failed).toContainText("stays in force");
  await expect(failed).toHaveClass(/text-amber/);
  const planner = applied.getByRole("status", { name: "Schedule planner" });
  await expect(planner).toContainText("Schedule planner degraded: the schedule horizon ends within an hour");
  await expect(planner).toContainText(`planned until ${await page.evaluate((t) => new Date(t).toLocaleString(), horizonEnd)}`);
  await expect(planner).toContainText("set refill: netlink busy");
  await expect(planner).toHaveClass(/text-amber/);
});

test("a healthy installed ruleset reads quietly", async ({ page }) => {
  await mockAPI(page, {
    enforcement: { state: "enforcing", reason: "" },
    engineStatus: {
      appliedAt: "2026-10-26T06:00:00Z", snapshotVersion: "v41",
      schedulePlanner: { lastRefill: "2026-10-26T06:00:00Z", horizonEnd: "2026-10-27T06:00:00Z", state: "ok" },
    },
  });
  await open(page, "/firewall/");
  await page.getByRole("button", { name: "Preview", exact: true }).click();
  const applied = page.getByRole("region", { name: "Applied ruleset" });
  await expect(applied).toContainText("in force since");
  await expect(applied.getByRole("status", { name: "Failed apply" })).toHaveCount(0);
  await expect(applied.getByRole("status", { name: "Schedule planner" })).toContainText("Schedule planner: ok.");
  await expect(applied.getByRole("status", { name: "Schedule planner" })).not.toHaveClass(/text-amber/);
});

test("enforcement health and status times are read defensively", () => {
  expect(normalizeEnforcementHealth(undefined)).toBeUndefined();
  expect(normalizeEnforcementHealth({ state: "degraded", reason: "x" })).toEqual({ state: "degraded", reason: "x" });
  expect(normalizeEnforcementHealth({ state: "paused" })).toEqual({ state: "unknown", reason: "" });
  expect(formatStatusTime("0001-01-01T00:00:00Z")).toBeNull();
  expect(formatStatusTime(undefined)).toBeNull();
  expect(formatStatusTime("not a time")).toBe("not a time");
});
