import { expect, test, type Page } from "@playwright/test";

import { normalizeManagementRecovery } from "../lib/api-health";

// GET /health reports boot recovery (managementRecovery) with or without a
// management reservation. The shell shows it in amber on every page while it
// is anything but inactive, from one health poll the page shares.

const user = { id: "admin-1", username: "containd", role: "admin", mfaRequired: false };

async function mockAPI(page: Page, managementRecovery: unknown, seen: { health: number } = { health: 0 }) {
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    let body: unknown = {};
    if (path === "/api/v1/auth/me" || path === "/api/v1/auth/session") body = user;
    if (path === "/api/v1/health") {
      seen.health++;
      body = { status: "ok", component: "mgmt", managementRecovery };
    }
    if (path === "/api/v1/firewall/rules") body = [];
    if (path === "/api/v1/zones" || path === "/api/v1/conntrack") body = [];
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

for (const path of ["/firewall/", "/ics/", "/zones/", "/sessions/"]) {
  test(`${path} shows active boot recovery in amber`, async ({ page }) => {
    await mockAPI(page, { state: "active", reason: "stored configuration refused at boot" });
    await open(page, path);
    const banner = page.getByRole("status", { name: "Boot recovery" });
    await expect(banner).toHaveCount(1);
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

test("the shell and the page share one health poll every 30 seconds", async ({ page }) => {
  const seen = { health: 0 };
  // Waits until no health request arrives for half a second of real time.
  const settled = async () => {
    await expect.poll(async () => {
      const before = seen.health;
      await page.waitForTimeout(500);
      return seen.health === before;
    }).toBe(true);
    return seen.health;
  };
  await page.clock.install();
  await mockAPI(page, { state: "pending", reason: "" }, seen);
  // The ICS page reads health for its own indicators too.
  await open(page, "/ics/");
  await expect(page.getByRole("status", { name: "Boot recovery" })).toContainText("pending");
  // Stop the clock, so only runFor moves it: every 30 s window holds
  // exactly one tick of a shared 30 s poll, whatever its phase.
  await page.clock.pauseAt(Date.now() + 5_000);
  const base = await settled();
  await page.clock.runFor(30_000);
  expect(await settled()).toBe(base + 1);
  await page.clock.runFor(30_000);
  expect(await settled()).toBe(base + 2);
});
