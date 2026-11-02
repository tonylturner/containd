import { expect, test, type Page } from "@playwright/test";
import type { Asset } from "../lib/api";

async function mockAssets(page: Page, role = "admin") {
  const state = {
    assets: [{ id: "plc", name: "PLC", hostnames: ["old.example"], tags: ["keep"] }] as Asset[],
    writes: [] as { body: Partial<Asset>; revision?: string }[],
    clears: 0, failSave: false, failClear: false,
  };
  await page.addInitScript(r => localStorage.setItem("containd.auth.role", r), role);
  await page.route("**/api/v1/**", async route => {
    const req = route.request();
    const path = new URL(req.url()).pathname.replace("/api/v1", "");
    if (path.startsWith("/assets") && ["PATCH", "POST"].includes(req.method())) {
      const body = req.postDataJSON();
      state.writes.push({ body, revision: req.headers()["x-containd-if-revision"] });
      if (state.failSave) return route.fulfill({ status: 412, json: { error: "changed", code: "config_revision_mismatch", currentRevision: "0123456789abcdef.2" } });
      const asset = { ...(req.method() === "PATCH" ? state.assets[0] : {}), ...body };
      state.assets = req.method() === "PATCH" ? [asset] : [...state.assets, asset];
      return route.fulfill({ json: asset, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
    }
    if (path === "/inventory" && req.method() === "DELETE") {
      state.clears++;
      return route.fulfill({ status: state.failClear ? 503 : 200, json: state.failClear ? { error: "inventory unavailable" } : { status: "cleared" } });
    }
    const json = path.startsWith("/auth/") ? { id: "admin", role }
      : path === "/assets" ? state.assets
      : path === "/zones" ? [{ name: "ot" }]
      : path === "/inventory/iec104" ? { pairs: [], limits: { pairs: 10, casPerPair: 10, pointsPerCA: 10, maxIdleSeconds: 3600 }, overflow: {} }
      : path === "/config/diff" ? { changed: false, changedSections: [] } : {};
    return route.fulfill({ json, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  const loaded = page.waitForResponse(r => r.url().endsWith("/api/v1/assets"));
  await page.goto("/assets/");
  await loaded;
  return state;
}

test("asset hostnames create, edit and explicit clear stage with revision and preserve other metadata", async ({ page }) => {
  const state = await mockAssets(page);
  await page.getByPlaceholder("id (e.g. plc-1)").fill("hmi");
  await page.getByPlaceholder("name", { exact: true }).fill("HMI");
  await page.getByLabel("Hostnames (comma-separated)", { exact: true }).fill(" hmi.example, hmi.local ");
  await page.getByRole("button", { name: "Create asset", exact: true }).click();
  await expect.poll(() => state.writes.length).toBe(1);
  expect(state.writes[0]).toMatchObject({ revision: "0123456789abcdef.1", body: { hostnames: ["hmi.example", "hmi.local"] } });
  const row = page.getByRole("row").filter({ has: page.getByRole("cell", { name: "plc", exact: true }) });
  await row.getByRole("button", { name: "Edit", exact: true }).click();
  const modal = page.getByRole("dialog", { name: "Edit asset plc", exact: true });
  await expect(modal.getByLabel("Hostnames (comma-separated)")).toHaveValue("old.example");
  await modal.getByLabel("Hostnames (comma-separated)").fill("new.example");
  await modal.getByRole("button", { name: "Save changes", exact: true }).click();
  await expect(modal).toHaveCount(0);
  expect(state.writes[1]).toMatchObject({ revision: "0123456789abcdef.1", body: { hostnames: ["new.example"], tags: ["keep"] } });
  await row.getByRole("button", { name: "Edit", exact: true }).click();
  await modal.getByLabel("Hostnames (comma-separated)").fill("");
  await modal.getByRole("button", { name: "Save changes", exact: true }).click();
  await expect(modal).toHaveCount(0);
  expect(state.writes[2].body.hostnames).toEqual([]);
});

test("asset hostname draft survives a revision conflict", async ({ page }) => {
  const state = await mockAssets(page);
  state.failSave = true;
  await page.getByRole("button", { name: "Edit", exact: true }).click();
  const modal = page.getByRole("dialog");
  await modal.getByLabel("Hostnames (comma-separated)").fill("retained.example");
  await modal.getByRole("button", { name: "Save changes", exact: true }).click();
  await expect.poll(() => state.writes.length).toBe(1);
  await expect(modal.getByLabel("Hostnames (comma-separated)")).toHaveValue("retained.example");
});

for (const fail of [false, true]) {
  test(`inventory clear requires confirmation and ${fail ? "shows failure" : "refreshes observations only"}`, async ({ page }) => {
    const state = await mockAssets(page);
    state.failClear = fail;
    const clear = page.getByRole("button", { name: "Clear inventory (immediate)", exact: true });
    await clear.click();
    await expect(page.getByRole("dialog")).toContainText("Configured assets and learner datasets are unchanged");
    expect(state.clears).toBe(0);
    await page.getByRole("dialog").getByRole("button", { name: "Cancel", exact: true }).click();
    expect(state.clears).toBe(0);
    await clear.click();
    await page.getByRole("dialog").getByRole("button", { name: "Clear inventory", exact: true }).click();
    await expect.poll(() => state.clears).toBe(1);
    await expect(page.getByText(fail ? "inventory unavailable" : "Observed inventory cleared immediately.", { exact: false })).toBeVisible();
    expect(state.assets[0].hostnames).toEqual(["old.example"]);
    expect(state.writes).toEqual([]);
  });
}

test("asset and inventory mutations are hidden from viewers", async ({ page }) => {
  await mockAssets(page, "viewer");
  await expect(page.getByRole("button", { name: "Edit", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Clear inventory (immediate)", exact: true })).toHaveCount(0);
});
