import { expect, test, type Page } from "@playwright/test";

import { at, snapshot } from "./fixtures/iec104-inventory";

async function mock(page: Page, response: () => { status: number; body: unknown }) {
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    let body: unknown = {};
    let status = 200;
    if (path.endsWith("/inventory/iec104")) ({ body, status } = response());
    else if (["/assets", "/zones", "/interfaces", "/interfaces/state"].some((p) => path.endsWith(p))) body = [];
    else if (path.endsWith("/auth/me") || path.endsWith("/auth/session")) body = { id: "admin", username: "operator", role: "admin" };
    else if (path.endsWith("/health")) body = { status: "ok", iec104Enforcement: { active: false, healthy: true } };
    await route.fulfill({ status, contentType: "application/json", body: JSON.stringify(body), headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
}

for (const mobile of [false, true]) {
  test(`passive IEC 104 stations, points and overflow${mobile ? " on mobile" : ""}`, async ({ page }) => {
    if (mobile) await page.setViewportSize({ width: 390, height: 844 });
    const errors: string[] = [];
    page.on("pageerror", (err) => errors.push(String(err)));
    await mock(page, () => ({ status: 200, body: snapshot }));
    await page.goto("/assets");
    const panel = page.getByRole("region", { name: "Passive IEC 104 inventory" });
    await expect(panel).toContainText("never generates auto-ALLOW rules");
    await expect(panel).toContainText("inline enforce mode only");
    await expect(panel).toContainText("Monitor and non-inline capture never claim delivery");
    await expect(panel).toContainText("128 pairs · 32 CAs per pair · 256 points per CA");
    for (const [label, count] of [["Pairs", 2], ["CAs", 3], ["Points", 4], ["Lost outcomes", 8], ["Legacy assets", 5]] as const)
      await expect(panel).toContainText(`${label} overflow: ${count}`);
    await expect(panel.getByRole("table")).toHaveCount(0);
    await panel.locator("summary").filter({ hasText: "192.0.2.10:50000" }).click();
    await panel.locator("summary").filter({ hasText: "CA 7" }).click();
    await expect(panel).toContainText("3 attempted / 1 accepted");
    const points = panel.getByRole("table", { name: "CA 7 observed points" });
    await expect(points.getByRole("row")).toHaveCount(3);
    await expect(points.getByRole("cell", { name: "100", exact: true })).toHaveCount(2);
    await expect(points.getByRole("cell", { name: "45", exact: true })).toBeVisible();
    await expect(points.locator("time").first()).toHaveAttribute("dateTime", at);
    expect(errors).toEqual([]);
    if (!mobile && process.env.IEC104_INVENTORY_SCREENSHOT)
      await page.screenshot({ path: process.env.IEC104_INVENTORY_SCREENSHOT, fullPage: true });
  });
}

test("inventory unavailable is not empty or zero, and Refresh retries", async ({ page }) => {
  let offline = true;
  await mock(page, () => offline ? { status: 503, body: { error: "engine inventory unavailable" } } : { status: 200, body: snapshot });
  await page.goto("/assets");
  const panel = page.getByRole("region", { name: "Passive IEC 104 inventory" });
  await expect(panel.getByRole("status")).toContainText("IEC 104 inventory unavailable");
  await expect(panel).not.toContainText("No IEC 104 stations observed");
  await expect(panel.getByLabel("Inventory overflow counters")).toHaveCount(0);
  if (process.env.IEC104_INVENTORY_UNAVAILABLE_SCREENSHOT)
    await page.screenshot({ path: process.env.IEC104_INVENTORY_UNAVAILABLE_SCREENSHOT, fullPage: true });
  offline = false;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(panel).toContainText("192.0.2.20:2404");
  // A failed refresh must hide previously loaded counters too.
  offline = true;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  // The loaded panel has its own status badges until the refresh lands.
  await expect(panel.getByRole("status").filter({ hasText: "IEC 104 inventory unavailable" })).toBeVisible();
  await expect(panel).not.toContainText("3 attempted / 1 accepted");
});

test("reachable empty inventory is distinct from unavailable", async ({ page }) => {
  await mock(page, () => ({ status: 200, body: { ...snapshot, pairs: [] } }));
  await page.goto("/assets");
  await expect(page.getByText("No IEC 104 stations observed", { exact: true })).toBeVisible();
  await expect(page.getByText("IEC 104 inventory unavailable", { exact: false })).toHaveCount(0);
});
