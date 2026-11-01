import { expect, test, type Page } from "@playwright/test";

import { normalizeEnforcementHealth } from "../lib/api-health";
import { formatStatusTime } from "../app/firewall/firewall-ruleset-status";
import type { ProtectionStatus } from "../lib/api-protection";
import { observation } from "./fixtures/protection-api";

// Health's enforcement state is degraded while a ruleset is in force but the
// last apply failed or the schedule planner is degraded. The installed
// ruleset status, readable by every role, says why: the failed apply and the
// planner. The ruleset preview stays admin-only and is never its source.

const admin = { id: "admin-1", username: "containd", role: "admin", mfaRequired: false };
const viewer = { id: "viewer-1", username: "viewer", role: "view", mfaRequired: false };

type Mocks = {
  user?: typeof admin;
  enforcement?: unknown;
  protection?: ProtectionStatus;
  installed?: { status: number; json: unknown };
};

async function mockAPI(page: Page, mocks: Mocks): Promise<{ previewRequests: number }> {
  const user = mocks.user ?? admin;
  const seen = { previewRequests: 0 };
  await page.addInitScript((role) => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", role);
  }, user.role);
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/dataplane/ruleset/status") {
      await route.fulfill(mocks.installed ?? { status: 200, json: { installed: true, appliedAt: "2026-10-26T06:00:00Z" } });
      return;
    }
    let body: unknown = {};
    if (path === "/api/v1/auth/me" || path === "/api/v1/auth/session") body = user;
    if (path === "/api/v1/health") body = { status: "ok", component: "mgmt", enforcement: mocks.enforcement };
    if (path === "/api/v1/dataplane/protection") body = mocks.protection ?? observation({ state: "unknown" });
    if (path === "/api/v1/firewall/rules" || path === "/api/v1/zones") body = [];
    if (path === "/api/v1/routing") body = { gateways: [], routes: [], rules: [] };
    if (path === "/api/v1/dataplane") body = { captureInterfaces: [], dpiMock: false };
    if (path === "/api/v1/dataplane/ruleset") {
      seen.previewRequests++;
      body = { ruleset: "table inet containd_policy {}", runtime: { iec104EnvelopeOpen: false, reason: "no IEC 104 rules" } };
    }
    await route.fulfill({ json: body, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  return seen;
}

async function open(page: Page, path: string) {
  const loaded = Promise.all([
    page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/health"),
    page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/dataplane/ruleset/status"),
  ]);
  await page.goto(path);
  await loaded;
}

const failedAt = "2026-10-26T07:30:00Z";
const horizonEnd = "2026-10-26T08:10:00Z";
const degradedStatus = {
  installed: true, appliedAt: "2026-10-26T06:00:00Z", snapshotVersion: "v41",
  error: "nft: Error: Could not process rule", failedSnapshotVersion: "v42", failedAt,
  schedulePlanner: {
    lastRefill: "2026-10-25T08:10:00Z", horizonEnd, state: "degraded",
    reason: "the schedule horizon ends within an hour", lastError: "set refill: netlink busy", lastErrorAt: "2026-10-26T07:40:00Z",
  },
};

for (const path of ["/firewall/", "/ics/"]) {
  test(`${path} shows degraded enforcement in amber with protection's reason`, async ({ page }) => {
    await mockAPI(page, {
      enforcement: { state: "degraded", reason: "health summary without component detail" },
      protection: observation({ state: "degraded", retryable: true }),
    });
    await open(page, path);
    const indicator = page.getByRole("status", { name: "Firewall enforcement degraded: degraded" });
    await expect(indicator).toContainText("Rule-hit logging unavailable");
    await expect(indicator).not.toContainText("health summary without component detail");
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

for (const user of [admin, viewer]) {
  test(`the ${user.role} role sees why enforcement is degraded on the firewall page`, async ({ page }) => {
    const seen = await mockAPI(page, {
      user,
      enforcement: { state: "degraded", reason: "schedule planner degraded" },
      installed: { status: 200, json: degradedStatus },
    });
    await open(page, "/firewall/");
    const applied = page.getByRole("region", { name: "Applied ruleset" });
    await expect(applied).toContainText("in force since");
    await expect(applied).toContainText("Configuration ID: v41");
    const failed = applied.getByRole("status", { name: "Failed apply" });
    const failedText = await page.evaluate((t) => new Date(t).toLocaleString(), failedAt);
    await expect(failed).toContainText(`Last apply failed at ${failedText}`);
    await expect(failed).toContainText("Failed configuration ID: v42");
    await expect(failed.getByText("nft: Error: Could not process rule", { exact: true })).toBeVisible();
    await expect(failed).toContainText("stays in force");
    await expect(failed).toHaveClass(/text-amber/);
    const planner = applied.getByRole("status", { name: "Schedule planner" });
    await expect(planner.getByText("the schedule horizon ends within an hour", { exact: true })).toBeVisible();
    await expect(planner).toContainText(`ready until ${await page.evaluate((t) => new Date(t).toLocaleString(), horizonEnd)}`);
    await expect(planner.getByText(/Last update error.*set refill: netlink busy/)).toBeVisible();
    await expect(planner).toHaveClass(/text-amber/);
    expect(seen.previewRequests).toBe(0);
  });

  test(`the ${user.role} role sees why enforcement is degraded on the ICS page`, async ({ page }) => {
    const seen = await mockAPI(page, {
      user,
      enforcement: { state: "degraded", reason: "last ruleset apply failed; previous ruleset in force" },
      installed: { status: 200, json: degradedStatus },
    });
    await open(page, "/ics/");
    await expect(page.getByRole("status", { name: "Failed apply" })).toContainText("nft: Error: Could not process rule");
    await expect(page.getByRole("status", { name: "Schedule planner" })).toContainText("Schedules need attention.");
    await expect(page.getByRole("region", { name: "Applied ruleset" })).toHaveCount(0);
    expect(seen.previewRequests).toBe(0);
  });
}

test("a healthy installed ruleset reads quietly", async ({ page }) => {
  await mockAPI(page, {
    enforcement: { state: "enforcing", reason: "" },
    installed: { status: 200, json: {
      installed: true, appliedAt: "2026-10-26T06:00:00Z", snapshotVersion: "v41",
      schedulePlanner: { lastRefill: "2026-10-26T06:00:00Z", horizonEnd: "2026-10-27T06:00:00Z", state: "ok" },
    } },
  });
  await open(page, "/firewall/");
  const applied = page.getByRole("region", { name: "Applied ruleset" });
  await expect(applied).toContainText("in force since");
  await expect(applied.getByRole("status", { name: "Failed apply" })).toHaveCount(0);
  await expect(applied.getByRole("status", { name: "Schedule planner" })).toContainText("Scheduled-rule coverage ready.");
  await expect(applied.getByRole("status", { name: "Schedule planner" })).not.toHaveClass(/text-amber/);
});

test("the ICS page shows nothing extra while the installed ruleset is healthy", async ({ page }) => {
  await mockAPI(page, { enforcement: { state: "enforcing", reason: "" } });
  await open(page, "/ics/");
  await expect(page.getByRole("status", { name: "Firewall enforcing: healthy" })).toBeVisible();
  await expect(page.getByRole("status", { name: "Failed apply" })).toHaveCount(0);
  await expect(page.getByRole("status", { name: "Installed ruleset status" })).toHaveCount(0);
});

test("a released ruleset reads as none in force despite its apply time", async ({ page }) => {
  await mockAPI(page, {
    enforcement: { state: "disabled", reason: "" },
    installed: { status: 200, json: { installed: false, appliedAt: "2026-10-26T06:00:00Z", snapshotVersion: "v41" } },
  });
  await open(page, "/firewall/");
  await expect(page.getByRole("region", { name: "Applied ruleset" })).toContainText("Applied ruleset: none in force.");
});

for (const path of ["/firewall/", "/ics/"]) {
  test(`${path} says why the installed ruleset status is missing`, async ({ page }) => {
    await mockAPI(page, {
      enforcement: { state: "unknown", reason: "engine ruleset status unavailable" },
      installed: { status: 502, json: { error: "engine ruleset status unavailable: connection refused" } },
    });
    await open(page, path);
    await expect(page.getByRole("status", { name: "Installed ruleset status" }))
      .toContainText("engine ruleset status unavailable: connection refused");
    await expect(page.getByRole("region", { name: "Applied ruleset" })).toHaveCount(0);
  });
}

test("enforcement health and status times are read defensively", () => {
  expect(normalizeEnforcementHealth(undefined)).toBeUndefined();
  expect(normalizeEnforcementHealth({ state: "degraded", reason: "x" })).toEqual({ state: "degraded", reason: "x" });
  expect(normalizeEnforcementHealth({ state: "paused" })).toEqual({ state: "unknown", reason: "" });
  expect(formatStatusTime("0001-01-01T00:00:00Z")).toBeNull();
  expect(formatStatusTime(undefined)).toBeNull();
  expect(formatStatusTime("not a time")).toBe("not a time");
});
