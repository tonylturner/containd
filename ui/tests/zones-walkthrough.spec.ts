import { expect, test, type Page } from "@playwright/test";
import type { Zone } from "../lib/api";

async function mockZones(page: Page, fail = false) {
  let zones: Zone[] = [{ name: "ot", consequence: "Production loss" }];
  const writes: { body: Zone; revision?: string }[] = [];
  await page.addInitScript(() => localStorage.setItem("containd.auth.role", "admin"));
  await page.route("**/api/v1/**", async route => {
    const req = route.request();
    const path = new URL(req.url()).pathname.replace("/api/v1", "");
    if (path.startsWith("/zones") && req.method() !== "GET") {
      const body = req.postDataJSON();
      writes.push({ body, revision: req.headers()["x-containd-if-revision"] });
      if (fail) return route.fulfill({ status: 412, json: { error: "changed", code: "config_revision_mismatch", currentRevision: "0123456789abcdef.2" } });
      const zone = { ...zones.find(z => z.name === path.split("/")[2]), ...body };
      zones = req.method() === "POST" ? [...zones, zone] : [zone];
      return route.fulfill({ json: zone, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
    }
    const json = path.startsWith("/auth/") ? { id: "admin", role: "admin" }
      : path === "/zones" ? zones
      : path === "/security/conduits" ? []
      : path === "/config/diff" ? { changed: false, changedSections: [] } : {};
    await route.fulfill({ json, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  const loaded = page.waitForResponse(r => r.url().endsWith("/api/v1/zones"));
  await page.goto("/zones/");
  await loaded;
  return writes;
}

test("zone consequence supports create, edit and clear with candidate revision", async ({ page }) => {
  const writes = await mockZones(page);
  await page.getByLabel("Zone name", { exact: true }).fill("dmz");
  await page.getByLabel("Consequence", { exact: true }).fill("Service disruption");
  await page.getByRole("button", { name: "Create", exact: true }).click();
  await expect.poll(() => writes.length).toBe(1);
  expect(writes[0]).toMatchObject({ revision: "0123456789abcdef.1", body: { consequence: "Service disruption" } });
  const row = page.getByRole("row").filter({ has: page.getByRole("cell", { name: "ot", exact: true }) });
  await row.getByRole("button", { name: "Edit", exact: true }).click();
  await expect(row.getByLabel("Consequence")).toHaveValue("Production loss");
  await row.getByLabel("Consequence").fill("Safety impact");
  await row.getByRole("button", { name: "Save", exact: true }).click();
  await expect(row.getByRole("button", { name: "Edit", exact: true })).toBeVisible();
  expect(writes[1]).toMatchObject({ revision: "0123456789abcdef.1", body: { consequence: "Safety impact" } });
  await row.getByRole("button", { name: "Edit", exact: true }).click();
  await row.getByLabel("Consequence").fill("");
  await row.getByRole("button", { name: "Save", exact: true }).click();
  await expect(row.getByRole("button", { name: "Edit", exact: true })).toBeVisible();
  expect(writes[2].body.consequence).toBe("");
});

test("zone consequence edit survives revision conflict and cancel restores the saved value", async ({ page }) => {
  const writes = await mockZones(page, true);
  const row = page.getByRole("row").filter({ has: page.getByRole("cell", { name: "ot", exact: true }) });
  await row.getByRole("button", { name: "Edit", exact: true }).click();
  await row.getByLabel("Consequence").fill("Retained");
  await row.getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => writes.length).toBe(1);
  await expect(row.getByLabel("Consequence")).toHaveValue("Retained");
  await row.getByRole("button", { name: "Cancel", exact: true }).click();
  await row.getByRole("button", { name: "Edit", exact: true }).click();
  await expect(row.getByLabel("Consequence")).toHaveValue("Production loss");
});
