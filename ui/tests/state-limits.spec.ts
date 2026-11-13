import { expect, test, type Page } from "@playwright/test";

import { stateLimits as snapshot } from "./fixtures/state-limits";
import { formatBytes } from "../lib/utils";

test("IEC byte formatting shares sizing without changing existing short labels", () => {
  for (const [bytes, expected] of [[0, "0 B"], [512, "512 B"], [1024, "1 KiB"], [1536, "1.5 KiB"], [1048576, "1 MiB"], [2097152, "2 MiB"], [67108864, "64 MiB"], [1073741824, "1 GiB"]] as const) {
    expect(formatBytes(bytes, { iec: true })).toBe(expected);
  }
  expect(formatBytes(Number.NaN, { iec: true })).toBe("-");
  expect(formatBytes(1048576)).toBe("1.0 MB");
});

async function setup(page: Page) {
  const state = { fault: "", reject: false, counter: 1, writes: [] as { base?: string; body: Record<string, any> }[], config: { dpiEnabled: true, nfqueueGroup: 101, limits: { maxFlows: 32768 } } as Record<string, any> };
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async route => {
    const request = route.request();
    const path = new URL(request.url()).pathname.replace("/api/v1", "");
    const headers = { "X-Containd-Revision": `0123456789abcdef.${state.counter}` };
    if (path === "/diagnostics/state-limits") {
      return route.fulfill({ status: state.fault === "offline" ? 503 : 200, json: state.fault === "offline" ? { error: "offline" } : state.fault === "malformed" ? { tables: [], budget: {} } : state.fault === "bad-category" ? { ...snapshot, budget: { ...snapshot.budget, byCategory: { stream: null } } } : snapshot });
    }
    if (path === "/dataplane" && request.method() === "POST") {
      state.writes.push({ base: request.headers()["x-containd-if-revision"], body: request.postDataJSON() });
      if (state.reject) return route.fulfill({ status: 400, json: { error: "dataplane.limits.maxFlows rejected by server validation" } });
      state.counter++;
      state.config = request.postDataJSON();
      return route.fulfill({ headers: { "X-Containd-Revision": `0123456789abcdef.${state.counter}`, "X-Containd-Config": "staged" }, json: state.config });
    }
    const data: Record<string, unknown> = {
      "/auth/me": { id: "admin", username: "containd", role: "admin" },
      "/auth/session": { id: "admin", username: "containd", role: "admin" },
      "/interfaces": [], "/interfaces/state": [], "/zones": [], "/firewall/rules": [],
      "/routing": {}, "/firewall/nat": {}, "/dataplane": state.config,
      "/health": { status: "ok", iec104Enforcement: { active: false, healthy: true } },
      "/config/diff": { changed: false, changedSections: [], running: {}, candidate: {} },
    };
    return route.fulfill({ headers, json: data[path] ?? {} });
  });
  return state;
}

for (const fault of ["", "offline", "malformed", "bad-category"]) {
  test(`state limits ${fault || "live"} snapshot`, async ({ page }) => {
    const state = await setup(page);
    state.fault = fault;
    const loaded = page.waitForResponse("**/api/v1/diagnostics/state-limits");
    await page.goto("/diagnostics/");
    await loaded;
    const table = page.getByRole("table", { name: "Dataplane state limits", exact: true });
    if (fault) {
      await expect(page.getByRole("status").filter({ hasText: "State limits unavailable" })).toBeVisible();
      await expect(table).toHaveCount(0);
      state.fault = "";
      await expect(table).toBeVisible({ timeout: 10000 });
    } else {
      await expect(table.getByRole("row")).toHaveCount(13);
      const flows = table.getByRole("row").filter({ has: page.getByRole("rowheader", { name: "flows", exact: true }) });
      await expect(flows).toContainText("16,384");
      await expect(flows).toContainText("2,048");
      await expect(flows).toContainText("17 refused / enforce");
      await expect(flows).toContainText("Recent hit");
      await expect(flows.getByRole("cell").nth(3)).toHaveText("4,096");
      const inspection = table.getByRole("row").filter({ has: page.getByRole("rowheader", { name: "inspection_bytes", exact: true }) });
      await expect(inspection.getByRole("cell")).toHaveText(["64 MiB", "0", "1 MiB", "2 MiB", "", ""]);
      await expect(table.getByRole("status")).toHaveCount(1);
      await expect(page.getByText("Inspection charges by category:", { exact: false })).toContainText("stream 512 KiB · decoder 512 KiB · held 0 B · pairing 0 B");
      await expect(table).toContainText("No aggregate cap");
      if (process.env.STATE_LIMITS_SCREENSHOT) await table.locator("../..").screenshot({ path: process.env.STATE_LIMITS_SCREENSHOT });
      await page.setViewportSize({ width: 390, height: 844 });
      await expect(table.getByRole("rowheader", { name: "flows", exact: true })).toBeVisible();
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    }
  });
}

test("state limits settings preserve defaults, show validation and stage with revision", async ({ page }) => {
  const state = await setup(page);
  const loaded = page.waitForResponse("**/api/v1/dataplane");
  await page.goto("/firewall/");
  await loaded;
  await expect(page.getByRole("button", { name: /^DPI settings/ })).toHaveAttribute("aria-expanded", "true");
  const settings = page.getByRole("region", { name: "Traffic state limits", exact: true });
  await expect(settings.getByText("Effective candidate: 32768", { exact: false })).toBeVisible();
  await expect(settings.getByText("default: 8192", { exact: false })).toBeVisible();
  await settings.getByLabel("Directional flow slots", { exact: false }).fill("1023");
  await settings.getByRole("button", { name: "Stage state limits" }).click();
  await expect(settings.getByRole("alert")).toContainText("1024–262144");
  expect(state.writes).toHaveLength(0);
  await settings.getByLabel("Directional flow slots", { exact: false }).fill("2048");
  state.reject = true;
  await settings.getByRole("button", { name: "Stage state limits" }).click();
  await expect(settings.getByRole("alert")).toContainText("rejected by server validation");
  await expect(settings.getByLabel("Directional flow slots", { exact: false })).toHaveValue("2048");
  state.reject = false;
  await settings.getByRole("button", { name: "Stage state limits" }).click();
  await expect(settings.getByRole("status")).toContainText("State limits staged");
  expect(state.writes.at(-1)).toEqual({ base: "0123456789abcdef.1", body: { dpiEnabled: true, nfqueueGroup: 101, limits: { maxFlows: 2048 } } });
  expect(state.writes).toHaveLength(2);
});
