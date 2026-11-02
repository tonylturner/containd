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
    await route.fulfill({ json: body, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
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

test("DHCP keeps fixed line boxes, square info tips and keyboard focus", async ({ page }) => {
  await page.goto("/dhcp");
  await page.evaluate(() => document.fonts.ready);
  const label = page.locator("label").filter({ hasText: "Authoritative" }).first();
  await expect(label).toHaveCSS("line-height", "20px");
  const tip = label.getByRole("img");
  await expect(tip).toHaveCSS("height", "16px");
  await expect(tip).toHaveCSS("width", "16px");
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

for (const [path, placeholder] of [
  ["/identities", "Search addresses or identities..."],
  ["/zones", "Search zones..."],
  ["/audit", "Search audit log..."],
  ["/alerts", "Search alerts by message, ID, anomaly type, IP..."],
  ["/ids", "Search rules..."],
] as const) {
  test(`${path} search text starts clear of its icon`, async ({ page }) => {
    await page.route("**/api/v1/identities", (route) => route.fulfill({ json: { mappings: [{ ip: "10.0.0.5", identities: ["ops"] }] }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } }));
    await page.route("**/api/v1/zones", (route) => route.fulfill({ json: [{ name: "ot" }], headers: { "X-Containd-Revision": "0123456789abcdef.1" } }));
    await page.route("**/api/v1/audit", (route) => route.fulfill({ json: [], headers: { "X-Containd-Revision": "0123456789abcdef.1" } }));
    await page.route("**/api/v1/events?*", (route) => route.fulfill({ json: [], headers: { "X-Containd-Revision": "0123456789abcdef.1" } }));
    await page.route("**/api/v1/ids/rules", (route) => route.fulfill({ json: { enabled: true, rules: [{ id: "r1", title: "rule" }] }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } }));
    await page.goto(path);
    const input = page.getByPlaceholder(placeholder, { exact: true });
    await expect(input).toHaveCSS("padding-left", "36px");
    const icon = input.locator("xpath=preceding-sibling::*[local-name()='svg']");
    const iconBox = (await icon.boundingBox())!;
    const inputBox = (await input.boundingBox())!;
    expect(iconBox.x + iconBox.width).toBeLessThan(inputBox.x + 36);
  });
}

test("a toolbar search field fits its placeholder", async ({ page }) => {
  await page.route("**/api/v1/identities", (route) => route.fulfill({ json: { mappings: [{ ip: "10.0.0.5", identities: ["ops"] }] }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } }));
  await page.goto("/identities");
  const input = page.getByPlaceholder("Search addresses or identities...", { exact: true });
  await expect(input).toBeVisible();
  expect(await input.evaluate((el: HTMLInputElement) => {
    const probe = document.createElement("span");
    probe.style.cssText = `font: ${getComputedStyle(el).font}; visibility: hidden; position: absolute; white-space: pre`;
    probe.textContent = el.placeholder;
    document.body.append(probe);
    const fits = probe.getBoundingClientRect().width <= el.clientWidth - 36 - 12;
    probe.remove();
    return fits;
  })).toBe(true);
});
