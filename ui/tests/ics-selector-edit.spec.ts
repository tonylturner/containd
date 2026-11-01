import { expect, test } from "@playwright/test";
import { effectivePredicate } from "../app/ics/ics-shared";
import { openEditor } from "./fixtures/ics-editor";

const user = { id: "admin-1", username: "containd", role: "admin", mfaRequired: false };


for (const surface of ["ics", "firewall"]) {
  const save = surface === "ics" ? "Save filter" : "Save changes";
  for (const [text, codes] of [["", undefined], [" ", undefined], ["3,", [3]], [",,3,,", [3]], ["0", [0]]] as const) {
    test(`${surface}: ${JSON.stringify(text)} preview equals save`, async ({ page }) => {
      const seen = await openEditor(page, surface, { protocol: "modbus", direction: "request" });
      const form = page.locator("div.fixed.inset-0");
      await form.getByPlaceholder("3, 16").fill(text);
      await form.getByRole("button", { name: "Preview impact" }).click();
      await expect.poll(() => seen.previews.length).toBe(1);
      await form.getByRole("button", { name: save }).click();
      await expect.poll(() => seen.patches.length).toBe(1);
      expect(seen.previews[0].ics).toEqual(effectivePredicate(seen.patches[0].ics));
      expect(seen.patches[0].ics.functionCode).toEqual(codes);
      expect(seen.patches[0].ics.direction).toBe("request");
    });
  }

  for (const protocol of ["modbus", "cip"]) {
    test(`${surface}: clearing stored ${protocol} restrictions survives reload`, async ({ page }) => {
      const seen = await openEditor(page, surface, {
        protocol, functionCode: [3], direction: "response",
        ...(protocol === "modbus" ? { unitId: 0, addresses: ["0-10"] } : { objectClasses: [4] }),
      });
      const form = page.locator("div.fixed.inset-0");
      await form.getByPlaceholder(protocol === "modbus" ? "3, 16" : surface === "ics" ? "76, 77" : "0x4C, 0x4D, 0x52").fill("");
      if (protocol === "modbus") {
        await form.getByPlaceholder(surface === "ics" ? "0-255 (leave empty for all)" : "e.g. 1").fill("");
        await form.getByLabel("Register / coil addresses").fill("");
      } else {
        await form.getByPlaceholder(surface === "ics" ? "0x02, 0x04 (leave empty for all)" : "0x02, 0x04, 0x66").fill("");
      }
      await form.getByRole("button", { name: "Preview impact" }).click();
      await expect.poll(() => seen.previews.length).toBe(1);
      const reloaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/firewall/rules" && r.request().method() === "GET");
      await form.getByRole("button", { name: save }).click();
      await reloaded;
      expect(seen.previews[0].ics).toEqual(effectivePredicate(seen.patches[0].ics));
      expect(seen.patches[0].ics).toMatchObject({ functionCode: null, ...(protocol === "modbus" ? { unitId: null, addresses: null } : { objectClasses: null }) });
      expect(seen.saved().ics).toMatchObject({ protocol, direction: "response" });
      expect(seen.saved().ics?.functionCode).toBeUndefined();
      expect(seen.saved().ics?.unitId).toBeUndefined();
      expect(seen.saved().ics?.objectClasses).toBeUndefined();
      await page.getByRole("button", { name: "Edit", exact: true }).click();
      await expect(page.locator("div.fixed.inset-0").getByPlaceholder(protocol === "modbus" ? "3, 16" : surface === "ics" ? "76, 77" : "0x4C, 0x4D, 0x52")).toHaveValue("");
    });
  }

  test(`${surface}: inheriting mode previews the exact saved predicate`, async ({ page }) => {
    const seen = await openEditor(page, surface, { protocol: "modbus", mode: "enforce", functionCode: [3] });
    const form = page.locator("div.fixed.inset-0");
    await form.getByLabel(surface === "ics" ? "Safety mode" : "Rule Mode").selectOption("");
    await form.getByRole("button", { name: "Preview impact" }).click();
    await expect.poll(() => seen.previews.length).toBe(1);
    await form.getByRole("button", { name: save }).click();
    await expect.poll(() => seen.patches.length).toBe(1);
    expect(seen.previews[0].ics).toEqual(effectivePredicate(seen.patches[0].ics));
    expect(seen.patches[0].ics.mode).toBeNull();
  });

  for (const token of ["3,no", "-1", "1.5", "256"]) {
    test(`${surface}: invalid ${token} blocks preview and save`, async ({ page }) => {
      const seen = await openEditor(page, surface, { protocol: "modbus" });
      const form = page.locator("div.fixed.inset-0");
      await form.getByPlaceholder("3, 16").fill(token);
      await expect(form.getByRole("alert")).toContainText("integer from 0 to 255");
      await form.getByRole("button", { name: "Preview impact" }).click();
      await form.getByRole("button", { name: save }).click();
      await expect(form).toBeVisible();
      expect(seen.previews).toEqual([]);
      expect(seen.patches).toEqual([]);
    });
  }
}

test("template preview renders nested rule protocol and codes", async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    let body: unknown = {};
    if (path === "/api/v1/auth/me" || path === "/api/v1/auth/session") body = user;
    if (path === "/api/v1/zones") body = [];
    if (path === "/api/v1/templates/ics") body = [{ name: "Read operations", protocol: "cip", description: "Read services" }];
    if (path === "/api/v1/templates/ics/apply") body = { rules: [{ id: "generated", description: "Generated read", action: "ALLOW", ics: { protocol: "cip", functionCode: [14, 76] } }, { id: "dnp-time", action: "ALLOW", ics: { protocol: "dnp3", functionCode: [2], groups: [50, 80] } }] };
    await route.fulfill({ json: body, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/templates/ics");
  await page.goto("/templates/");
  await loaded;
  await page.getByRole("button", { name: "Generate Rules" }).click();
  await page.locator("div.fixed.inset-0").getByRole("button", { name: "Preview", exact: true }).click();
  const row = page.getByRole("row").filter({ hasText: "generated" });
  await expect(row).toContainText("cip");
  await expect(row).toContainText("14, 76");
  await expect(page.getByRole("row").filter({ hasText: "dnp-time" })).toContainText("groups=50, 80");
});
