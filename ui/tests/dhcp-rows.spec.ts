import { expect, test, type Page } from "@playwright/test";
import type { DHCPConfig } from "../lib/api";

const legacyPayload: DHCPConfig = {
  enabled: true, authoritative: false, listenIfaces: ["lan2"], leaseSeconds: 3600,
  router: "", dnsServers: [], domain: "",
  pools: [{ iface: "lan2", start: "192.168.10.100", end: "192.168.10.200" }],
  reservations: [{ iface: "lan2", mac: "aa:bb:cc:dd:ee:ff", ip: "192.168.10.150" }],
};
async function setup(page: Page, loaded = false) {
  const state = { cfg: loaded ? legacyPayload : { ...legacyPayload, pools: [], reservations: [], listenIfaces: [] }, writes: [] as DHCPConfig[] };
  await page.route("**/api/v1/**", async route => {
    const req = route.request(), path = new URL(req.url()).pathname;
    if (path.endsWith("/services/dhcp") && req.method() === "POST") {
      expect(req.headers()["x-containd-if-revision"]).toBe("0123456789abcdef.1");
      state.cfg = req.postDataJSON(); state.writes.push(state.cfg);
    }
    const json = path.includes("/auth/") ? { id: "admin", role: "admin" }
      : path.endsWith("/services/dhcp") ? state.cfg
        : path.endsWith("/interfaces") ? [{ name: "lan2", alias: "Plant" }, { name: "lan3" }]
          : path.endsWith("/dhcp/leases") ? { leases: [] }
            : path.endsWith("/services/status") ? { faults: [], av: { available: false, error: "engine unavailable" }, dhcp: { enabled: true, sparkline: [], count: 0, rate_per_min: 0, errors_sparkline: [], errors_count: 0, errors_rate_per_min: 0 } }
              : path.endsWith("/config/diff") ? { changed: false, changedSections: [] } : {};
    return route.fulfill({ json, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  await Promise.all([page.waitForResponse("**/interfaces"), page.goto("/dhcp/")]);
  return state;
}

test("picker and rows stage exactly the old CSV payload without a hostname field", async ({ page }) => {
  const state = await setup(page);
  await page.getByRole("checkbox", { name: "lan2", exact: true }).check();
  await page.getByRole("button", { name: "Add pool", exact: true }).click();
  await page.getByRole("combobox", { name: "Pool 1 interface", exact: true }).selectOption("lan2");
  await page.getByLabel("Pool 1 start", { exact: true }).fill("192.168.10.100");
  await page.getByLabel("Pool 1 end", { exact: true }).fill("192.168.10.200");
  await page.getByText("Advanced options", { exact: true }).click();
  await page.getByRole("button", { name: "Add reservation", exact: true }).click();
  await page.getByRole("combobox", { name: "Reservation 1 interface", exact: true }).selectOption("lan2");
  await page.getByLabel("Reservation 1 MAC", { exact: true }).fill("aa:bb:cc:dd:ee:ff");
  await page.getByLabel("Reservation 1 IP", { exact: true }).fill("192.168.10.150");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => state.writes.length).toBe(1);
  expect(state.writes[0]).toEqual(legacyPayload);
});

for (const [label, value, error] of [
  ["Pool 1 start", "300.0.0.1", "Pool 1:"],
  ["Pool 1 start", "192.168.10.201", "ascending order"],
  ["Reservation 1 MAC", "aa:", "valid MAC"],
  ["Reservation 1 IP", "192.168.10.99", "inside a pool"],
]) {
  test(`rows refuse ${label} ${value} without a request`, async ({ page }) => {
    const state = await setup(page, true);
    await expect(page.locator("details").filter({ has: page.getByText("Advanced options", { exact: true }) })).toHaveAttribute("open", "");
    await page.getByLabel(label, { exact: true }).fill(value);
    await page.getByRole("button", { name: "Save", exact: true }).click();
    await expect(page.getByText(error, { exact: false }).first()).toBeVisible();
    expect(state.writes).toEqual([]);
  });
}

test("saved pool and reservation rows round-trip and remove on a phone without overflow", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const state = await setup(page, true);
  await expect(page.getByLabel("Reservation 1 MAC", { exact: true })).toHaveValue("aa:bb:cc:dd:ee:ff");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => state.writes.length).toBe(1);
  expect(state.writes[0]).toEqual(legacyPayload);
  await page.getByRole("button", { name: "Remove reservation", exact: true }).click();
  await page.getByRole("button", { name: "Remove pool", exact: true }).click();
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => state.writes.length).toBe(2);
  expect(state.writes[1].pools).toEqual([]);
  expect(state.writes[1].reservations).toEqual([]);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});
