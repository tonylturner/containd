import { expect, test } from "@playwright/test";

const revision = "0123456789abcdef.1";
const iface = { name: "lan1", device: "eth2", zone: "lan" };
const runtime = { name: "eth2", index: 2, up: true, mtu: 1500, addrs: ["192.0.2.2/24"] };

test.beforeEach(async ({ page }) => {
  await page.route("**/api/v1/**", async route => {
    const path = new URL(route.request().url()).pathname;
    const json = path.includes("/auth/") ? { id: "admin", username: "containd", role: "admin" }
      : path === "/api/v1/interfaces" ? [iface]
      : path === "/api/v1/interfaces/state" ? [runtime]
      : path === "/api/v1/zones" ? [{ name: "lan" }]
      : path === "/api/v1/config/diff" ? { changed: false, changedSections: [] } : {};
    await route.fulfill({ json, headers: { "X-Containd-Revision": revision } });
  });
});

for (const width of [1280, 390]) {
  test(`network setup separates steps, NAT and counts at ${width}px`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 844 });
    const loaded = page.waitForResponse(response => new URL(response.url()).pathname === "/api/v1/interfaces");
    await page.goto("/interfaces/");
    await loaded;
    const setup = page.getByRole("navigation", { name: "Network setup", exact: true });
    const steps = setup.getByRole("list", { name: "Network setup steps", exact: true });
    await expect(steps.getByRole("listitem")).toHaveCount(4);
    await expect(steps.getByRole("link")).toHaveText(["Zones", "Logical interfaces", "Connectivity", "Review"]);
    await expect(steps.getByRole("link", { name: "NAT", exact: true })).toHaveCount(0);
    const nat = setup.getByRole("link", { name: "NAT", exact: true });
    await expect(nat).toHaveAttribute("href", "/nat/");
    const counts = page.getByText("Logical interfaces: 1 · Live devices: 1", { exact: true });
    await expect(counts).toBeVisible();
    await expect(setup).not.toContainText("Live devices:");
    await page.evaluate(() => document.fonts.ready);
    const stepsBox = (await steps.boundingBox())!;
    const natBox = (await nat.boundingBox())!;
    const countsBox = (await counts.boundingBox())!;
    expect(natBox.x >= stepsBox.x + stepsBox.width + 12 || natBox.y >= stepsBox.y + stepsBox.height + 8).toBe(true);
    expect(countsBox.y).toBeGreaterThanOrEqual(Math.max(stepsBox.y + stepsBox.height, natBox.y + natBox.height) + 4);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.screenshot({ path: testInfo.outputPath(`network-setup-${width}.png`) });
  });

  for (const attention of ["unknown", "customized"] as const) {
    test(`interface ${attention} metadata stays with Device while Inspect is closed at ${width}px`, async ({ page }) => {
      await page.setViewportSize({ width, height: 844 });
      if (attention === "unknown") {
        await page.route("**/api/v1/interfaces/state", route => route.fulfill({ json: [] }));
      } else {
        await page.route("**/api/v1/interfaces", route => route.fulfill({ json: [{
          ...iface, addressMode: "static", addresses: ["192.0.2.2/24"], gateway: "192.0.2.1",
          access: { mgmt: true, http: false, https: true, ssh: true },
        }], headers: { "X-Containd-Revision": revision } }));
        await page.route("**/api/v1/interfaces/state", route => route.fulfill({ json: [{ ...runtime, up: false }] }));
      }
      const writes: string[] = [];
      page.on("request", request => {
        if (request.url().includes("/api/v1/") && request.method() !== "GET") writes.push(request.url());
      });
      await page.goto("/interfaces/");
      const row = page.getByRole("row").filter({ has: page.getByRole("cell", { name: "lan1", exact: true }) });
      const device = row.getByRole("cell").nth(2);
      const actions = row.getByRole("cell").last();
      const inspect = row.getByRole("button", { name: "Inspect", exact: true });
      await expect(inspect).toHaveAttribute("aria-expanded", attention === "customized" ? "true" : "false");
      if (attention === "customized") await inspect.click();
      await expect(inspect).toHaveAttribute("aria-expanded", "false");
      const summary = attention === "unknown"
        ? "external · physical · Live unknown"
        : "static · physical · Link down · Access customized · Gateway set";
      await expect(device.getByText(summary, { exact: true })).toBeVisible();
      await expect(actions).not.toContainText("physical");
      await expect(actions.getByRole("button")).toHaveText(["Inspect", "Edit", "Delete"]);
      await inspect.click();
      await expect(inspect).toHaveAttribute("aria-expanded", "true");
      await inspect.click();
      await expect(inspect).toHaveAttribute("aria-expanded", "false");
      await expect(device.getByText(summary, { exact: true })).toBeVisible();
      expect(writes).toEqual([]);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    });
  }
}
