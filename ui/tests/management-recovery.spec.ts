import { expect, test, type Page } from "@playwright/test";

import { normalizeManagementRecovery } from "../lib/api-console";

// GET /health reports boot recovery (managementRecovery) with or without a
// management reservation. Pages that show runtime health show it in amber
// while it is anything but inactive.

const user = { id: "admin-1", username: "containd", role: "admin", mfaRequired: false };

async function mockAPI(page: Page, managementRecovery: unknown) {
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    let body: unknown = {};
    if (path === "/api/v1/auth/me" || path === "/api/v1/auth/session") body = user;
    if (path === "/api/v1/health") body = { status: "ok", component: "mgmt", managementRecovery };
    if (path === "/api/v1/firewall/rules") body = [];
    if (path === "/api/v1/zones") body = [];
    if (path === "/api/v1/routing") body = { gateways: [], routes: [], rules: [] };
    if (path === "/api/v1/dataplane") body = { captureInterfaces: [], dpiMock: false };
    await route.fulfill({ json: body });
  });
}

async function open(page: Page, path: string) {
  const health = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/health");
  await page.goto(path);
  await health;
}

for (const path of ["/firewall/", "/ics/"]) {
  test(`${path} shows active boot recovery in amber`, async ({ page }) => {
    await mockAPI(page, { state: "active", reason: "stored configuration refused at boot" });
    await open(page, path);
    const banner = page.getByRole("status", { name: "Boot recovery" });
    await expect(banner).toContainText("Boot recovery active: new transit dropped");
    await expect(banner).toContainText("stored configuration refused at boot");
    await expect(banner).toContainText("Commit a safe configuration");
    await expect(banner).toHaveClass(/text-amber/);
    await expect(banner.getByRole("link", { name: "Interfaces" })).toHaveAttribute("href", "/interfaces/");
  });
}

for (const [state, title] of [
  ["pending", "Boot recovery pending: recovery ruleset not applied"],
  ["failed", "Boot recovery failed: recovery ruleset not applied"],
  ["unknown", "Boot recovery state unknown"],
] as const) {
  test(`firewall names ${state} boot recovery`, async ({ page }) => {
    await mockAPI(page, { state, reason: "" });
    await open(page, "/firewall/");
    await expect(page.getByRole("status", { name: "Boot recovery" })).toContainText(title);
  });
}

test("inactive or absent recovery shows nothing", async ({ page }) => {
  await mockAPI(page, { state: "inactive", reason: "" });
  await open(page, "/firewall/");
  await expect(page.getByRole("heading", { name: "Firewall Rules", exact: true })).toBeVisible();
  await expect(page.getByRole("status", { name: "Boot recovery" })).toHaveCount(0);
  await mockAPI(page, undefined);
  await open(page, "/ics/");
  await expect(page.getByRole("status", { name: "Boot recovery" })).toHaveCount(0);
});

test("recovery health is read defensively", () => {
  expect(normalizeManagementRecovery(undefined)).toBeUndefined();
  expect(normalizeManagementRecovery({ state: "active", reason: "x" })).toEqual({ state: "active", reason: "x" });
  expect(normalizeManagementRecovery({ state: "rebooting" })).toEqual({ state: "unknown", reason: "" });
});
