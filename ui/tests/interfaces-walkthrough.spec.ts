import { expect, test } from "@playwright/test";

for (const width of [390, 1280]) {
  test(`interface actions stay reachable and editing retains one draft at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    const writes: unknown[] = [];
    await page.addInitScript(() => localStorage.setItem("containd.auth.role", "admin"));
    await page.route("**/api/v1/**", async route => {
      const req = route.request();
      const path = new URL(req.url()).pathname.replace("/api/v1", "");
      if (req.method() === "PATCH") {
        writes.push(req.postDataJSON());
        return route.fulfill({ json: { name: "lan1", ...req.postDataJSON() }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
      }
      const json = path.startsWith("/auth/") ? { id: "admin", role: "admin" }
        : path === "/interfaces" ? [{ name: "lan1", device: "eth1", zone: "ot", addresses: ["192.0.2.1/24"] }]
        : path === "/interfaces/state" ? [{ name: "eth1", up: true, addrs: ["192.0.2.1/24"] }]
        : path === "/zones" ? [{ name: "ot" }]
        : path === "/config/diff" ? { changed: false, changedSections: [] } : {};
      await route.fulfill({ json, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
    });
    const loaded = page.waitForResponse(r => r.url().endsWith("/api/v1/interfaces"));
    await page.goto("/interfaces/");
    await loaded;
    const table = page.getByRole("table", { name: "Configured interfaces" });
    const edit = table.getByRole("button", { name: "Edit", exact: true });
    await edit.scrollIntoViewIfNeeded();
    const bounds = (await edit.boundingBox())!;
    expect(bounds.x).toBeGreaterThanOrEqual(0);
    expect(bounds.x + bounds.width).toBeLessThanOrEqual(width);
    expect(await table.evaluate(el => el.scrollWidth <= el.clientWidth)).toBe(true);
    await edit.focus();
    await page.keyboard.press("Enter");
    await table.getByPlaceholder("alias (optional)").fill("Retained alias");
    await page.setViewportSize({ width: width === 390 ? 1280 : 390, height: 900 });
    await expect(table.getByPlaceholder("alias (optional)")).toHaveValue("Retained alias");
    await table.getByRole("button", { name: "Save", exact: true }).scrollIntoViewIfNeeded();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await table.getByRole("button", { name: "Cancel", exact: true }).click();
    await expect(table.getByRole("button", { name: "Inspect", exact: true })).toBeFocused();
    expect(writes).toEqual([]);
  });
}
