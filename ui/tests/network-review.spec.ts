import { expect, test } from "@playwright/test";
import { CONFIG_COMMITTED } from "../lib/config-events";

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
      : path === "/api/v1/routing" ? { gateways: [], routes: [], rules: [] }
      : path === "/api/v1/firewall/nat" ? { enabled: false, sourceZones: [] }
      : path === "/api/v1/firewall/rules" ? []
      : path === "/api/v1/config/diff" ? { changed: false, changedSections: [], running: {}, candidate: {} } : {};
    await route.fulfill({ json, headers: { "X-Containd-Revision": revision } });
  });
});

test("failed interface config refresh leaves retained inspection and live Retry operable without authorizing writes", async ({ page }) => {
  let configUnavailable = false;
  let runtimeUnavailable = true;
  const writes: string[] = [];
  page.on("request", request => {
    if (request.url().includes("/api/v1/") && request.method() !== "GET") writes.push(request.url());
  });
  await page.route("**/api/v1/interfaces", route => route.fulfill(configUnavailable
    ? { status: 503, json: { error: "Configuration read failed" } }
    : { json: [iface], headers: { "X-Containd-Revision": revision } }));
  await page.route("**/api/v1/interfaces/state", route => route.fulfill(runtimeUnavailable
    ? { status: 503, json: { error: "Runtime read failed" } }
    : { json: [runtime] }));
  await page.goto("/interfaces/");
  const unavailable = page.getByRole("status").filter({ hasText: "Live device information is unavailable" });
  await expect(unavailable).toBeVisible();
  configUnavailable = true;
  await page.evaluate(event => window.dispatchEvent(new CustomEvent(event)), CONFIG_COMMITTED);
  const configError = page.getByRole("alert").filter({ hasText: "Configuration unavailable" });
  await expect(configError).toBeVisible();
  const inspect = page.getByRole("button", { name: "Inspect", exact: true });
  await expect(inspect).toBeEnabled();
  await inspect.click();
  await expect(inspect).toHaveAttribute("aria-expanded", "true");
  await expect(page.getByText("MTU: Unknown", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Edit", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Delete", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Create", exact: true })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Auto-assign", exact: true })).toBeDisabled();
  runtimeUnavailable = false;
  await unavailable.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(unavailable).toHaveCount(0);
  await expect(page.getByText("MTU: 1500", { exact: true })).toBeVisible();
  await expect(page.getByText("Detected address: 192.0.2.2/24", { exact: true })).toBeVisible();
  await expect(configError).toBeVisible();
  await expect(page.getByRole("button", { name: "Create", exact: true })).toBeDisabled();
  expect(writes).toEqual([]);
});

for (const path of ["/zones/", "/interfaces/", "/routing/", "/nat/"]) {
  test(`${path} setup distinguishes logical interfaces and links Review directly to diff without writes`, async ({ page }) => {
    const writes: string[] = [];
    page.on("request", request => {
      if (request.url().includes("/api/v1/") && request.method() !== "GET") writes.push(request.url());
    });
    await page.goto(path);
    const setup = page.getByRole("navigation", { name: "Network setup", exact: true });
    await expect(setup.getByRole("link", { name: "Logical interfaces", exact: true })).toHaveAttribute("href", "/interfaces/");
    await expect(setup.getByRole("link", { name: "Network devices", exact: true })).toHaveCount(0);
    if (path === "/interfaces/") await expect(page.getByRole("heading", { name: "Detected network devices", exact: true })).toBeVisible();
    const review = setup.getByRole("link", { name: "Review", exact: true });
    await expect(review).toHaveAttribute("href", "/config/?tab=diff");
    await review.click();
    await expect(page).toHaveURL(/\/config\/\?tab=diff$/);
    expect(writes).toEqual([]);
  });
}
