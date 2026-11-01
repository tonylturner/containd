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
    await route.fulfill({ json: body, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
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

for (const width of [1280, 390]) {
  test(`expanded navigation has settled readable contrast at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 844 });
    await openZones(page);
    if (width === 390) await page.getByRole("button", { name: "Navigation", exact: true }).click();
    const nav = page.getByRole("navigation", { name: "Main navigation" });
    const policy = nav.getByRole("button", { name: "Policy & Rules", exact: true });
    if (await policy.getAttribute("aria-expanded") === "false") await policy.click();
    const network = nav.getByRole("button", { name: "Network", exact: true });
    if (await network.getAttribute("aria-expanded") === "false") await network.click();
    await expect(nav.getByRole("link", { name: "Firewall Rules", exact: true })).toBeVisible();
    await expect(nav.getByRole("link", { name: "Zones", exact: true })).toHaveAttribute("aria-current", "page");
    await nav.evaluate(async (element) => {
      await Promise.all(element.getAnimations({ subtree: true }).map((animation) => animation.finished));
    });
    const samples = await nav.locator("a, button").evaluateAll((elements) => {
      const canvas = document.createElement("canvas");
      canvas.width = canvas.height = 1;
      const ctx = canvas.getContext("2d")!;
      const rgba = (color: string) => {
        ctx.clearRect(0, 0, 1, 1);
        ctx.fillStyle = color;
        ctx.fillRect(0, 0, 1, 1);
        return [...ctx.getImageData(0, 0, 1, 1).data].map((n) => n / 255);
      };
      const blend = (front: number[], back: number[]) =>
        back.map((n, i) => front[i] * front[3] + n * (1 - front[3]));
      const luminance = (rgb: number[]) => rgb.slice(0, 3).reduce((sum, n, i) =>
        sum + (n <= 0.04045 ? n / 12.92 : ((n + 0.055) / 1.055) ** 2.4) * [0.2126, 0.7152, 0.0722][i], 0);
      return elements.map((element) => {
        const ancestors: Element[] = [];
        for (let el: Element | null = element; el; el = el.parentElement) ancestors.unshift(el);
        let background = [1, 1, 1];
        let opacity = 1;
        for (const el of ancestors) {
          const style = getComputedStyle(el);
          background = blend(rgba(style.backgroundColor), background);
          opacity *= Number(style.opacity);
        }
        const color = rgba(getComputedStyle(element).color);
        color[3] *= opacity;
        const foreground = blend(color, background);
        const a = luminance(foreground), b = luminance(background);
        return { text: element.textContent?.trim(), opacity, contrast: (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05) };
      });
    });
    await test.info().attach("navigation-contrast", { body: JSON.stringify(samples, null, 2), contentType: "application/json" });
    await page.screenshot({ path: test.info().outputPath(`navigation-settled-${width}.png`), fullPage: true });
    for (const sample of samples) {
      expect(sample.opacity, sample.text).toBe(1);
      expect(sample.contrast, sample.text).toBeGreaterThanOrEqual(4.5);
    }
  });
}
