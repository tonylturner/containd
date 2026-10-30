import { expect, test } from "@playwright/test";

test("a service stays loading until every requested refresh has settled", async ({ page }) => {
  await page.route("**/api/v1/**", (route) => {
    const path = new URL(route.request().url()).pathname;
    const json = path.endsWith("/auth/me") || path.endsWith("/auth/session")
      ? { id: "admin", username: "containd", role: "admin" }
      : path.endsWith("/config/diff") ? { changed: false }
      : path.endsWith("/services/dns") ? { enabled: true, listenPort: 53 } : {};
    return route.fulfill({ json });
  });
  const initial = page.waitForResponse("**/api/v1/services/dns");
  await page.goto("/system/services/dns/");
  await initial;
  await expect(page.locator("main .animate-pulse")).toHaveCount(0);

  const releases: Array<() => void> = [];
  await page.route("**/api/v1/services/dns", async (route) => {
    await new Promise<void>((resolve) => { releases.push(resolve); });
    await route.fulfill({ json: { enabled: true, listenPort: 53 } });
  });
  await page.getByRole("button", { name: "Refresh", exact: true }).evaluate((button: HTMLButtonElement) => {
    button.click();
    button.click();
  });
  await expect.poll(() => releases.length).toBe(2);
  await expect(page.locator("main .animate-pulse").first()).toBeVisible();
  const first = page.waitForResponse("**/api/v1/services/dns");
  releases[0]();
  await first;
  await expect(page.locator("main .animate-pulse").first()).toBeVisible();
  const second = page.waitForResponse("**/api/v1/services/dns");
  releases[1]();
  await second;
  await expect(page.locator("main .animate-pulse")).toHaveCount(0);
});

test("a background NAT refresh keeps the existing draft mounted while awaiting IO", async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem("containd.auth.role", "admin"));
  await page.route("**/api/v1/**", (route) => {
    const path = new URL(route.request().url()).pathname;
    const json = path.endsWith("/auth/me") || path.endsWith("/auth/session")
      ? { id: "admin", username: "containd", role: "admin" }
      : path.endsWith("/config/diff") ? { changed: false }
      : path.endsWith("/zones") ? [{ name: "wan" }, { name: "lan" }]
      : path.endsWith("/firewall/nat") ? { enabled: true, egressZone: "wan", portForwards: [] } : {};
    return route.fulfill({ json });
  });
  const initial = page.waitForResponse("**/api/v1/firewall/nat");
  await page.goto("/nat/");
  await initial;
  const draft = page.getByPlaceholder("dest ip");
  await draft.fill("192.0.");
  let release!: () => void;
  const held = new Promise<void>((resolve) => { release = resolve; });
  await page.route("**/api/v1/firewall/nat", async (route) => {
    await held;
    await route.fulfill({ json: { enabled: true, egressZone: "wan", portForwards: [] } });
  });
  const requested = page.waitForRequest("**/api/v1/firewall/nat");
  await page.evaluate(() => window.dispatchEvent(new Event("containd:config:staged")));
  await requested;
  await expect(draft).toHaveValue("192.0.");
  await expect(page.locator("main .animate-pulse")).toHaveCount(0);
  const answered = page.waitForResponse("**/api/v1/firewall/nat");
  release();
  await answered;
  await expect(draft).toHaveValue("192.0.");
});
