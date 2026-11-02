import { expect, test, type Page, type Response } from "@playwright/test";
import type { DHCPConfig } from "../lib/api";
import { CONFIG_COMMITTED, CONFIG_STAGED } from "../lib/config-events";

// The event meter every management service status entry carries.
const idleMeter = {
  sparkline: [], count: 0, rate_per_min: 0, errors_sparkline: [], errors_count: 0, errors_rate_per_min: 0,
};

type Server = {
  config: DHCPConfig;
  writes: DHCPConfig[];
  /** While set, config reads answer only after it resolves. */
  hold: Promise<void> | null;
};

/** Mocks the API around one DHCP config. A write stores it and reports it staged. */
async function mockAPI(page: Page, config: DHCPConfig): Promise<Server> {
  const server: Server = { config, writes: [], hold: null };
  await page.route("**/api/v1/**", async (route) => {
    const req = route.request();
    const path = new URL(req.url()).pathname;
    if (path.endsWith("/services/dhcp")) {
      if (req.method() === "POST") {
        server.config = req.postDataJSON() as DHCPConfig;
        server.writes.push(server.config);
        return route.fulfill({ json: server.config, headers: { "X-Containd-Revision": "0123456789abcdef.1", "X-Containd-Config": "staged" } });
      }
      if (server.hold) await server.hold;
      return route.fulfill({ json: server.config, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
    }
    const data = path.endsWith("/auth/me") || path.endsWith("/auth/session")
      ? { id: "admin-1", username: "containd", role: "admin" }
      : path.endsWith("/interfaces") ? [{ name: "lan2" }, { name: "lan3" }]
      : path.endsWith("/dhcp/leases") ? { leases: [] }
        : path.endsWith("/services/status") ? { faults: [], dhcp: { enabled: false, ...idleMeter }, av: { available: false, error: "engine unavailable" } }
          : path.endsWith("/config/diff") ? { changed: false, changedSections: [] } : {};
    await route.fulfill({ json: data, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  return server;
}

const configRead = (r: Response) => new URL(r.url()).pathname.endsWith("/services/dhcp") && r.request().method() === "GET";

// The dev server compiles the page on first visit, which can outlast the
// default assertion timeout; wait for the page to read its config instead.
async function open(page: Page) {
  await Promise.all([page.waitForResponse(configRead), page.goto("/dhcp/")]);
}

/** Another editor's staged or committed change, as the page learns of it. */
async function announceConfigChange(page: Page) {
  await Promise.all([
    page.waitForResponse(configRead),
    page.evaluate((name) => window.dispatchEvent(new CustomEvent(name)), CONFIG_COMMITTED),
  ]);
}

/** Resolves once a refresh has applied: the live status card is drawn again. */
function settled(page: Page) {
  return expect(page.getByText(/^Pools:/)).toBeVisible();
}

const authority = (page: Page) => page.getByRole("checkbox", { name: /^Authoritative/ });
const save = (page: Page) => page.getByRole("button", { name: "Save", exact: true });
const notice = (page: Page) => page.getByRole("status", { name: "Unsaved edits" });

for (const stored of [undefined, false, true]) {
  test(`DHCP authority ${String(stored)} loads, saves and refreshes`, async ({ page }) => {
    const server = await mockAPI(page, { enabled: false, ...(stored === undefined ? {} : { authoritative: stored }) });
    await open(page);
    await expect(authority(page)).toBeEnabled();
    if (stored === true) await expect(authority(page)).toBeChecked();
    else await expect(authority(page)).not.toBeChecked();
    await expect(notice(page)).toHaveCount(0);
    // Saving without editing must preserve the stored/default value.
    await save(page).click();
    await expect.poll(() => server.writes.length).toBe(1);
    expect(server.writes[0].authoritative).toBe(stored ?? false);
    await authority(page).setChecked(!(stored ?? false));
    await save(page).click();
    await expect.poll(() => server.writes.length).toBe(2);
    expect(server.writes[1].authoritative).toBe(!(stored ?? false));
    await Promise.all([page.waitForResponse(configRead), page.reload()]);
    if (stored === true) await expect(authority(page)).not.toBeChecked();
    else await expect(authority(page)).toBeChecked();
  });
}

test("an edit made while the staged refresh is in flight survives it", async ({ page }) => {
  const server = await mockAPI(page, { enabled: false, authoritative: true });
  await open(page);
  await expect(authority(page)).toBeChecked();
  // A save reports the config staged, which makes the page reload its config.
  // Hold that reload until after the next edit, as a slow server would.
  let release!: () => void;
  server.hold = new Promise<void>((resolve) => { release = resolve; });
  const reload = page.waitForResponse(configRead);
  await save(page).click();
  await expect.poll(() => server.writes.length).toBe(1);
  await authority(page).setChecked(false);
  await expect(notice(page)).toHaveText(/Unsaved edits/);
  release();
  await reload;
  await settled(page);
  await expect(authority(page)).not.toBeChecked();
  await expect(notice(page)).not.toHaveText(/changed on the server/);
  await save(page).click();
  await expect.poll(() => server.writes.length).toBe(2);
  expect(server.writes[1].authoritative).toBe(false);
  await expect(notice(page)).toHaveCount(0);
});

test("a server change under unsaved edits is kept and announced until Refresh", async ({ page }) => {
  const server = await mockAPI(page, { enabled: false, authoritative: false });
  await open(page);
  await authority(page).setChecked(true);
  server.config = { enabled: false, authoritative: false, domain: "ops.lab" };
  await announceConfigChange(page);
  await settled(page);
  await expect(authority(page)).toBeChecked();
  await expect(notice(page)).toHaveText(/changed on the server/);
  expect(server.writes).toHaveLength(0);
  await page.getByRole("button", { name: "Refresh", exact: true }).first().click();
  await expect(authority(page)).not.toBeChecked();
  await expect(notice(page)).toHaveCount(0);
});

test("a clean editor adopts a server change", async ({ page }) => {
  const server = await mockAPI(page, { enabled: false, authoritative: false });
  await open(page);
  await expect(authority(page)).not.toBeChecked();
  server.config = { enabled: false, authoritative: true };
  await announceConfigChange(page);
  await expect(authority(page)).toBeChecked();
  await expect(notice(page)).toHaveCount(0);
});

test("DHCP keeps unfinished row and DNS edits across config refreshes", async ({ page }) => {
  await mockAPI(page, { enabled: false, authoritative: false });
  await open(page);
  await page.getByText("Advanced options", { exact: true }).click();
  await page.getByRole("button", { name: "Add pool", exact: true }).click();
  await page.getByRole("button", { name: "Add reservation", exact: true }).click();
  const pool = page.getByLabel("Pool 1 start", { exact: true });
  const reservation = page.getByLabel("Reservation 1 MAC", { exact: true });
  const dns = page.getByPlaceholder("192.168.1.1, 1.1.1.1");
  await pool.fill("192.");
  await reservation.fill("aa:");
  await dns.fill("192.168.");
  for (const event of [CONFIG_COMMITTED, CONFIG_STAGED]) {
    await Promise.all([
      page.waitForResponse(configRead),
      page.evaluate((name) => window.dispatchEvent(new CustomEvent(name)), event),
    ]);
    await settled(page);
    await expect(pool).toHaveValue("192.");
    await expect(reservation).toHaveValue("aa:");
    await expect(dns).toHaveValue("192.168.");
  }
  await page.getByRole("button", { name: "Refresh", exact: true }).first().click();
  await expect(pool).toHaveCount(0);
  await expect(reservation).toHaveCount(0);
  await expect(page.getByRole("checkbox", { name: /^lan2/ })).toBeChecked();
});
