import { expect, test, type Page } from "@playwright/test";

const meter = { sparkline: [], count: 0, rate_per_min: 0, errors_sparkline: [], errors_count: 0, errors_rate_per_min: 0 };

async function setup(page: Page, mode?: string, failure?: string) {
  const writes: { path: string; body: Record<string, unknown>; base?: string }[] = [];
  await page.route("**/api/v1/**", async route => {
    const req = route.request(), path = new URL(req.url()).pathname;
    if (req.method() === "POST") {
      const body = req.postData() ? req.postDataJSON() : {};
      writes.push({ path, body, base: req.headers()["x-containd-if-revision"] });
      return route.fulfill({ status: failure ? 400 : 200, json: failure ? { error: failure } : body, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
    }
    const json = path.includes("/auth/") ? { id: "admin", role: "admin" }
      : path.endsWith("/services/av") ? { enabled: true, ...(mode ? { mode } : {}), cacheTtl: 1500000000 }
        : path.endsWith("/services/status") ? { faults: [], av: { ...meter, available: true, enabled: true, ready: false, ready_error: "signature database required", clamav_running: false } }
          : path.endsWith("/zones") || path.endsWith("/assets") ? []
            : path.endsWith("/config/diff") ? { changed: false, changedSections: [] } : {};
    return route.fulfill({ json, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  await Promise.all([page.waitForResponse("**/services/av/defs"), page.goto("/system/services/av/")]);
  return writes;
}

test("omitted local mode offers recovery next to the database fault and confirms immediate update", async ({ page }) => {
  const writes = await setup(page);
  await expect(page.getByRole("button", { name: "Run definition update", exact: true })).toBeVisible();
  await expect(page.getByText("signature database required", { exact: false }).first()).toBeVisible();
  await page.getByRole("button", { name: "Update definitions", exact: true }).click();
  expect(writes).toEqual([]);
  await expect(page.getByRole("dialog")).toContainText("acts immediately");
  await page.getByRole("dialog").getByRole("button", { name: "Update definitions", exact: true }).click();
  await expect.poll(() => writes.length).toBe(1);
  expect(writes[0].path).toBe("/api/v1/services/av/update");
});

test("remote mode does not offer local definition updates", async ({ page }) => {
  await setup(page, "icap");
  await expect(page.getByRole("button", { name: "Run definition update", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Update definitions", exact: true })).toHaveCount(0);
});

test("cache duration loads and stages nanoseconds with a revision precondition", async ({ page }) => {
  const writes = await setup(page);
  await expect(page.getByLabel("Cache TTL (seconds)", { exact: true })).toHaveValue("1.5");
  await page.getByLabel("Cache TTL (seconds)", { exact: true }).fill("2.25");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => writes.length).toBe(1);
  expect(writes[0].body.cacheTtl).toBe(2250000000);
  expect(writes[0].body.mode).toBe("clamav");
  expect(writes[0].base).toBe("0123456789abcdef.1");
});

test("negative cache duration is refused before staging", async ({ page }) => {
  const writes = await setup(page);
  await page.getByLabel("Cache TTL (seconds)", { exact: true }).fill("-1");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByText("Cache TTL must be a non-negative duration representable in whole nanoseconds.")).toBeVisible();
  expect(writes).toEqual([]);
});

test("enforcement validation retains the cause and links to the existing control", async ({ page }) => {
  await setup(page, undefined, "services.av.scan.include needs dataplane.enforcement");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByText("services.av.scan.include needs dataplane.enforcement", { exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "Stage enforcement on the Firewall page" })).toHaveAttribute("href", "/firewall/#enforcement");
  await expect(page.getByText(/then retry Save and review both changes before committing/)).toBeVisible();
});

test("definition upload requires confirmation and cancellation sends nothing", async ({ page }) => {
  const writes = await setup(page);
  await page.locator('input[type="file"]').setInputFiles({ name: "custom.ndb", mimeType: "text/plain", buffer: Buffer.from("test signature") });
  await expect(page.getByRole("dialog")).toContainText("acts immediately");
  expect(writes).toEqual([]);
  await page.getByRole("dialog").getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  expect(writes).toEqual([]);
});

test("AV settings and recovery remain reachable at 390 px", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await setup(page);
  await page.getByRole("button", { name: "Update definitions", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Cancel", exact: true }).click();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});
