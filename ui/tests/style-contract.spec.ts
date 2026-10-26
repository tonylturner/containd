import { expect, test } from "@playwright/test";

test.use({ viewport: { width: 1280, height: 800 } });

test.beforeEach(async ({ page }) => {
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const body = path.endsWith("/auth/me") || path.endsWith("/auth/session")
      ? { id: "admin", username: "containd", role: "admin" }
      : path.endsWith("/dhcp/leases") ? { leases: [] }
        : path.endsWith("/config/diff") ? { changed: false, changedSections: [] }
          : {};
    await route.fulfill({ json: body });
  });
});

test("login retains the industrial palette, corners and input focus", async ({ page }) => {
  await page.goto("/login");
  const card = page.locator("div.max-w-md");
  await expect(card).toHaveCSS("border-color", "rgba(245, 158, 11, 0.15)");
  await expect(card).toHaveCSS("border-radius", "2px");
  await expect(card).toHaveCSS("background-color", "rgb(13, 17, 13)");
  await expect(card).toHaveCSS("color", "rgb(232, 213, 163)");
  const input = page.getByLabel("Username", { exact: true });
  await expect(input).toHaveCSS("font-size", "13px");
  await expect(input).toHaveCSS("border-radius", "2px");
  await input.focus();
  await expect(input).toHaveCSS("border-color", "rgb(245, 158, 11)");
  await expect(input).toHaveCSS("box-shadow", "rgba(245, 158, 11, 0.2) 0px 0px 0px 1px");
  await expect(page.getByRole("button", { name: "Login", exact: true })).toHaveCSS("cursor", "pointer");
});

test("DHCP keeps fixed line boxes, intrinsic info tips and keyboard focus", async ({ page }) => {
  await page.goto("/dhcp");
  await page.evaluate(() => document.fonts.ready);
  const label = page.locator("label").filter({ hasText: "Authoritative" }).first();
  await expect(label).toHaveCSS("line-height", "20px");
  const tip = label.getByRole("img");
  await expect(tip).toHaveCSS("height", "22px");
  expect((await tip.boundingBox())!.width).toBeLessThan(10);
  await tip.focus();
  await expect(tip).toHaveCSS("box-shadow", /rgb\(245, 158, 11\) 0px 0px 0px 4px/);
  await expect(label.getByRole("tooltip")).toHaveCSS("opacity", "1");
  await expect(label.getByRole("tooltip")).toHaveCSS("border-color", "rgba(245, 158, 11, 0.15)");
});

test("service navigation retains link colors, hover and subtle borders", async ({ page }) => {
  await page.goto("/system/services");
  const dashboard = page.getByRole("navigation", { name: "Main navigation" }).getByRole("link", { name: "Dashboard", exact: true });
  await expect(dashboard).toHaveCSS("color", "rgb(148, 163, 184)");
  await dashboard.hover();
  await expect(dashboard).toHaveCSS("color", "rgb(226, 232, 240)");
  await expect(page.getByRole("link", { name: "Configure →" }).first()).toHaveCSS("color", "rgb(232, 213, 163)");
});
