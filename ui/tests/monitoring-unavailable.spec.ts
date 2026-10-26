import { expect, test } from "@playwright/test";

// Exercise unavailable -> real empty -> unavailable after a successful read.
// Each endpoint retains its HTTP failure rather than being mocked as empty.
test.beforeEach(async ({ page }) => {
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const user = { id: "admin-1", username: "admin", role: "admin", mfaRequired: false };
    let body: unknown = {};
    if (path === "/api/v1/auth/me" || path === "/api/v1/auth/session") body = user;
    if (path === "/api/v1/interfaces" || path === "/api/v1/zones" || path === "/api/v1/events") body = [];
    if (path === "/api/v1/config/diff") body = { changed: false, running: {}, candidate: {} };
    if (path === "/api/v1/dashboard") body = { user, counts: { rules: 0, icsRules: 0 }, health: { hostname: "test" } };
    if (path === "/api/v1/system/stats") body = {
      cpu: { usagePercent: 0 }, memory: { totalBytes: 0, usagePercent: 0 },
      disk: { totalBytes: 0, usagePercent: 0 }, container: { running: true },
      runtime: { uptime: "1m", goroutines: 1 },
    };
    if (["/api/v1/flows", "/api/v1/interfaces/state", "/api/v1/simulation"].includes(path)) {
      await route.fulfill({ status: 503, json: { error: "engine unavailable" } });
    } else {
      await route.fulfill({ json: body });
    }
  });
});

test("flow failure is not an empty flow set and Retry recovers", async ({ page }, testInfo) => {
  let unavailable = true;
  await page.route("**/api/v1/flows?*", (route) => route.fulfill(unavailable
    ? { status: 503, json: { error: "engine flows unavailable" } }
    : { json: [] }));
  await page.goto("/flows/");
  await expect(page.getByRole("status").filter({ hasText: "Flows unavailable" })).toBeVisible();
  await expect(page.getByText("No flows yet", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Total flows: 0", { exact: true })).toHaveCount(0);
  await page.screenshot({ path: testInfo.outputPath("flows-unavailable.png"), fullPage: true });
  unavailable = false;
  await page.getByRole("status").filter({ hasText: "Flows unavailable" }).getByRole("button", { name: "Retry", exact: true }).click();
  await expect(page.getByText("No flows yet", { exact: true })).toBeVisible();
  unavailable = true;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: "Flows unavailable" })).toBeVisible();
  await expect(page.getByText("No flows yet", { exact: true })).toHaveCount(0);
});

test("interface failure differs from a reachable engine with no interfaces", async ({ page }) => {
  let unavailable = true;
  await page.route("**/api/v1/interfaces", (route) => route.fulfill({ json: [{ name: "configured-lan", device: "eth0", addresses: ["192.0.2.1/24"] }] }));
  await page.route("**/api/v1/interfaces/state", (route) => route.fulfill(unavailable
    ? { status: 503, json: { error: "engine interface state unavailable" } }
    : { json: [] }));
  await page.goto("/interfaces/");
  await expect(page.getByRole("status").filter({ hasText: "Interface runtime state unavailable" })).toBeVisible();
  await expect(page.getByText("No OS interfaces reported.", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("cell", { name: "configured-lan", exact: true })).toBeVisible();
  unavailable = false;
  await page.getByRole("status").filter({ hasText: "Interface runtime state unavailable" }).getByRole("button", { name: "Retry", exact: true }).click();
  await expect(page.getByText("No OS interfaces reported.", { exact: true })).toBeVisible();
  await expect(page.getByText("Interface runtime state unavailable")).toHaveCount(0);
});

test("simulation failure is unknown, not stopped, and Retry recovers", async ({ page }) => {
  let unavailable = true;
  await page.route("**/api/v1/simulation", (route) => route.fulfill(unavailable
    ? { status: 503, json: { error: "engine simulation unavailable" } }
    : { json: { running: false } }));
  await page.goto("/");
  const state = page.getByRole("status").filter({ hasText: "Simulation unavailable" });
  await expect(state).toBeVisible();
  await expect(page.getByTitle("Start traffic simulation")).toHaveCount(0);
  unavailable = false;
  await state.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(page.getByTitle("Start traffic simulation")).toBeVisible();
  unavailable = true;
  await page.getByTitle("Start traffic simulation").click();
  await expect(state).toBeVisible();
  await expect(page.getByTitle("Start traffic simulation")).toHaveCount(0);
});

test("monitoring overview does not fabricate zero flow counters", async ({ page }) => {
  await page.goto("/monitoring/");
  await expect(page.getByRole("status").filter({ hasText: "Flows unavailable" })).toBeVisible();
  await expect(page.getByText("No flow apps yet.", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Unknown", { exact: true })).toHaveCount(2);
});
