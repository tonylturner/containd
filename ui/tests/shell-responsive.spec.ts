import { expect, test, type Page } from "@playwright/test";

async function openZones(page: Page) {
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    let body: unknown = {};
    if (path === "/api/v1/auth/me") {
      body = { id: "admin-1", username: "containd", role: "admin" };
    } else if (path === "/api/v1/zones" || path === "/api/v1/interfaces") {
      body = [];
    } else if (path === "/api/v1/health") {
      body = { status: "ok", component: "mgmt" };
    }
    await route.fulfill({ json: body });
  });
  const data = page.waitForResponse((response) =>
    new URL(response.url()).pathname === "/api/v1/zones",
  );
  await page.goto("/zones/");
  await data;
  await expect(page.getByRole("heading", { name: "Zones", exact: true })).toBeVisible();
}

async function expectNoOverflow(page: Page) {
  expect(await page.evaluate(() =>
    document.documentElement.scrollWidth <= window.innerWidth,
  )).toBe(true);
}

test("390px shell leaves room for content and exposes navigation", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await openZones(page);
  await page.screenshot({ path: test.info().outputPath("shell-390.png"), fullPage: true });
  await expectNoOverflow(page);
  const main = page.getByRole("main", { name: "Zones", exact: true });
  expect((await main.boundingBox())?.width).toBe(390);
  const zoneName = page.getByLabel("Zone name", { exact: true });
  await zoneName.fill("ot");
  await expect(zoneName).toHaveValue("ot");
  const navigation = page.getByRole("navigation", { name: "Main navigation" });
  await expect(navigation).toBeHidden();
  const toggle = page.getByRole("button", { name: "Navigation", exact: true });
  await expect(toggle).toHaveAttribute("aria-expanded", "false");
  await toggle.click();
  await expect(toggle).toHaveAttribute("aria-expanded", "true");
  await expect(navigation).toBeVisible();
  await expectNoOverflow(page);
  await page.screenshot({ path: test.info().outputPath("shell-390-navigation.png"), fullPage: true });
  await navigation.getByRole("button", { name: "Network", exact: true }).click();
  await navigation.getByRole("link", { name: "Interfaces", exact: true }).click();
  await expect(page).toHaveURL(/\/interfaces\/$/);
  await expect(navigation).toBeHidden();
  await expect(page.getByRole("heading", { name: "Interfaces", exact: true })).toBeVisible();
});

for (const focus of ["toggle", "sidebar link", "page"] as const) {
  test(`mobile navigation closes with Escape from the ${focus}`, async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await openZones(page);
    const toggle = page.getByRole("button", { name: "Navigation", exact: true });
    const navigation = page.getByRole("navigation", { name: "Main navigation" });
    await toggle.click();
    await expect(navigation).toBeVisible();
    if (focus === "sidebar link") {
      await navigation.getByRole("link", { name: "Dashboard", exact: true }).focus();
    } else if (focus === "page") {
      await page.getByLabel("Zone name", { exact: true }).focus();
    } else {
      await expect(toggle).toBeFocused();
    }
    await page.keyboard.press("Escape");
    await expect(navigation).toBeHidden();
    await expect(toggle).toHaveAttribute("aria-expanded", "false");
    await expect(toggle).toBeFocused();
  });
}

test("mobile navigation closes with its toggle", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await openZones(page);
  const toggle = page.getByRole("button", { name: "Navigation", exact: true });
  const navigation = page.getByRole("navigation", { name: "Main navigation" });
  await toggle.click();
  await expect(navigation).toBeVisible();
  await toggle.click();
  await expect(navigation).toBeHidden();
});

test("1280px shell keeps the desktop sidebar", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 844 });
  await openZones(page);
  await expectNoOverflow(page);
  await expect(page.getByRole("button", { name: "Navigation", exact: true })).toBeHidden();
  await expect(page.getByRole("navigation", { name: "Main navigation" })).toBeVisible();
  expect((await page.getByRole("complementary", { name: "Sidebar" }).boundingBox())?.width).toBe(240);
  await page.screenshot({ path: test.info().outputPath("shell-1280.png"), fullPage: true });
});
