import type { Locator, Page, TestInfo } from "@playwright/test";
import { join } from "node:path";
import { expect, test } from "./fixtures/topology-test";
import { mockProtection } from "./fixtures/protection-api";

test.use({ viewport: { width: 1024, height: 768 } });

async function openMatrix(page: Page, count: number) {
  const names = ["it", "ot", "dmz", "scada", "lab", "cell", "vendor", "remote"].slice(0, count);
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const data: Record<string, unknown> = {
      "/api/v1/auth/me": { id: "admin", username: "containd", role: "admin" },
      "/api/v1/auth/session": { id: "admin", username: "containd", role: "admin" },
      "/api/v1/config/diff": { changed: false, changedSections: [] },
      "/api/v1/health": {
        status: "ok", component: "containd", evidence: { state: "ok" },
        enforcement: { state: "enforcing", reason: "" },
      },
      "/api/v1/zones": names.map((name) => ({ name, slTarget: 0 })),
      "/api/v1/security/conduits": [{
        from: "ot", to: "dmz",
        state: "allow", ids: "none", proto: [], traffic: 0, rules: [],
        gaps: [], mitre: [], defaultDeny: false, tlsEnforced: false,
        protoWhitelist: false, mfaRequired: false, auditLogged: true, avEnabled: false,
      }],
    };
    await route.fulfill({ json: data[path] ?? {}, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  await mockProtection(page);
  const loaded = page.waitForResponse("**/api/v1/security/conduits");
  await page.goto("/topology/");
  await page.getByRole("button", { name: "SECURITY", exact: true }).click();
  await loaded;
  const matrix = page.getByRole("region", { name: "Zone conduit matrix", exact: true });
  // Six zones are selected initially; exercise adding zones beyond that default.
  for (const name of names.slice(6)) {
    await page.getByPlaceholder("+ Add zone...").fill(name);
    await page.locator('[class*="zoneDropdownItem"]').filter({ hasText: name.toUpperCase() }).click();
  }
  await expect(matrix.locator('[class*="colHeader"]')).toHaveCount(count);
  return matrix;
}

async function expectInside(container: Locator, column: Locator) {
  await expect.poll(async () => {
    const bounds = await container.evaluate((el) => {
      const left = el.getBoundingClientRect().left + el.clientLeft;
      return { left, right: left + el.clientWidth };
    });
    const box = await column.boundingBox();
    if (!box) return false;
    return box.x >= bounds.left && box.x + box.width <= bounds.right;
  }, "the entire last column must be inside the matrix viewport").toBe(true);
}

async function expectPageFits(page: Page) {
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
}

async function screenshot(page: Page, info: TestInfo, name: string) {
  await page.screenshot({
    animations: "disabled",
    path: process.env.TOPOLOGY_SCREENSHOT_DIR
      ? join(process.env.TOPOLOGY_SCREENSHOT_DIR, name)
      : info.outputPath(name),
  });
}

test("four zones fit at 1024 px, including when conduit details are open", async ({ page }, info) => {
  const matrix = await openMatrix(page, 4);
  const grid = matrix.locator('[class*="gridWrap"]');
  await expectInside(matrix, matrix.locator('[class*="colHeader"]').last());
  await expectInside(matrix, matrix.locator('[class*="gridRow"]').first().locator(':scope > [class*="cell"]').last());
  await expect.poll(() => matrix.evaluate((el) => el.scrollWidth <= el.clientWidth)).toBe(true);
  // All four rows fit initially, not just their column headers.
  await expect.poll(async () => {
    const viewport = await matrix.boundingBox();
    const box = await grid.boundingBox();
    const height = await page.evaluate(() => innerHeight);
    return !!viewport && !!box && box.y >= viewport.y
      && box.y + box.height <= Math.min(viewport.y + viewport.height, height);
  }).toBe(true);
  await expectPageFits(page);
  await screenshot(page, info, "security-4-zones.png");

  await matrix.getByText("ALLOW", { exact: true }).click();
  await expect(page.getByRole("region", { name: "Conduit details" })).toBeVisible();
  await expectInside(matrix, matrix.locator('[class*="colHeader"]').last());
  await expectPageFits(page);
  await screenshot(page, info, "security-4-zones-details.png");
});

test("eight zones scroll within the matrix at 1024 px", async ({ page }, info) => {
  const matrix = await openMatrix(page, 8);
  await expect.poll(() => matrix.evaluate((el) => el.scrollWidth > el.clientWidth)).toBe(true);
  await expectInside(matrix, matrix.locator('[class*="colHeader"]').first());
  await expectPageFits(page);
  await screenshot(page, info, "security-8-zones-start.png");
  await matrix.evaluate((el) => { el.scrollLeft = el.scrollWidth; });
  await expectInside(matrix, matrix.locator('[class*="colHeader"]').last());
  await expectInside(matrix, matrix.locator('[class*="gridRow"]').first().locator(':scope > [class*="cell"]').last());
  await expectPageFits(page);
  await screenshot(page, info, "security-8-zones-end.png");
  await matrix.evaluate((el) => { el.scrollLeft = 0; });
  await expectInside(matrix, matrix.locator('[class*="rowHeader"]').first());
  await page.getByTitle("Zoom in", { exact: true }).click();
  await matrix.evaluate((el) => Promise.all(el.getAnimations({ subtree: true }).map((animation) => animation.finished)));
  await matrix.evaluate((el) => { el.scrollLeft = el.scrollWidth; });
  await expectInside(matrix, matrix.locator('[class*="colHeader"]').last());
  await expectPageFits(page);
});

test("a fitting matrix stays centered on wide screens", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  const matrix = await openMatrix(page, 4);
  const viewport = await matrix.boundingBox();
  const grid = await matrix.locator('[class*="gridWrap"]').boundingBox();
  await expect(page.getByRole("region", { name: "Conduit details" })).toBeVisible();
  expect(viewport).not.toBeNull();
  expect(grid).not.toBeNull();
  expect(Math.abs((grid!.x + grid!.width / 2) - (viewport!.x + viewport!.width / 2))).toBeLessThan(1);
  await expectPageFits(page);
});
