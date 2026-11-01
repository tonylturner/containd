import { expect, test, type Page } from "@playwright/test";

import { routes } from "./fixtures/routes";

// Every page must survive a server answering 200 with the wrong shape: a list
// endpoint returning an object, string or null. A malformed body reads as
// unavailable, never as a crash or as a verified-empty list.

const user = { id: "admin-1", username: "containd", role: "admin", mfaRequired: false };

for (const [name, body] of [["object", { unexpected: true }], ["string", "unexpected"], ["null", null]] as const) {
  for (const path of routes) {
    test(`${path} survives ${name} bodies`, async ({ page }) => {
      const pageErrors: string[] = [];
      page.on("pageerror", (err) => pageErrors.push(String(err)));
      await page.addInitScript(() => {
        localStorage.setItem("containd.auth.token", "test-token");
        localStorage.setItem("containd.auth.role", "admin");
      });
      await page.route("**/api/v1/**", async (route) => {
        const p = new URL(route.request().url()).pathname;
        if (p === "/api/v1/auth/me" || p === "/api/v1/auth/session") {
          await route.fulfill({ json: user, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
          return;
        }
        await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body), headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
      });
      await page.goto(path);
      await page.waitForLoadState("networkidle");
      expect(pageErrors).toEqual([]);
      await expect(page.getByText("Application error")).toHaveCount(0);
    });
  }
}

for (const [path, endpoint, message] of [
  ["/alerts", "/api/v1/events", "Failed to load alerts."],
  ["/flows", "/api/v1/flows", "Flows unavailable"],
  ["/templates", "/api/v1/templates/ics", "ICS templates unavailable"],
  ["/sessions", "/api/v1/conntrack", "malformed connection list"],
] as const) {
  test(`${path} reports a non-list ${endpoint} body as unavailable`, async ({ page }) => {
    const pageErrors: string[] = [];
    page.on("pageerror", (err) => pageErrors.push(String(err)));
    await page.addInitScript(() => {
      localStorage.setItem("containd.auth.token", "test-token");
      localStorage.setItem("containd.auth.role", "admin");
    });
    await page.route("**/api/v1/**", async (route) => {
      const p = new URL(route.request().url()).pathname;
      const body = p === "/api/v1/auth/me" || p === "/api/v1/auth/session" ? user
        : p === endpoint ? { items: [{ id: 1 }] }
          : p.endsWith("/config/diff") ? { changed: false, changedSections: [] } : [];
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body), headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
    });
    await page.goto(path);
    await expect(page.getByText(message, { exact: false }).first()).toBeVisible();
    expect(pageErrors).toEqual([]);
  });
}

for (const [name, body] of [["object", { unexpected: true }], ["string", "unexpected"]] as const) {
  for (const view of ["PHYSICAL", "SECURITY"]) {
    test(`topology ${view} view survives ${name} bodies`, async ({ page }) => {
      const pageErrors: string[] = [];
      page.on("pageerror", (err) => pageErrors.push(String(err)));
      await page.route("**/api/v1/**", async (route) => {
        const p = new URL(route.request().url()).pathname;
        const json = p === "/api/v1/auth/me" || p === "/api/v1/auth/session" ? user : body;
        await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(json), headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
      });
      await page.goto("/topology/");
      await page.getByRole("button", { name: view, exact: true }).click();
      await page.waitForLoadState("networkidle");
      expect(pageErrors).toEqual([]);
      await expect(page.getByText("Application error")).toHaveCount(0);
    });
  }
}

// A page that loaded a healthy list must also report a later malformed
// answer as unavailable, whether a poll, the Refresh button, a config change
// or an action refetches it, and hide the earlier list rather than keep
// presenting it as current.

const malformed = { unexpected: true };

/**
 * Mocks the API with `bodies` per path ([] for other lists). After
 * breakList() the `endpoint` answers 200 with a non-list body.
 */
async function mockHealthyThenMalformed(page: Page, endpoint: string, bodies: Record<string, unknown>) {
  let broken = false;
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const p = new URL(route.request().url()).pathname;
    const body = p === "/api/v1/auth/me" || p === "/api/v1/auth/session" ? user
      : p === endpoint && broken ? malformed
        : p in bodies ? bodies[p]
          : p.endsWith("/config/diff") ? { changed: false, changedSections: [] } : [];
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body), headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  return {
    /** Breaks the list; resolves once the next fetch of it has answered. */
    breakList: () => {
      broken = true;
      return page.waitForResponse((r) => new URL(r.url()).pathname === endpoint);
    },
  };
}

async function openHealthy(page: Page, path: string, endpoint: string) {
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === endpoint);
  await page.goto(path);
  await loaded;
}

const committed = (page: Page) => page.evaluate(() => window.dispatchEvent(new CustomEvent("containd:config:committed")));

const alert = { id: "7", flowId: "f-7", proto: "ids", kind: "alert", timestamp: "2026-10-26T08:00:00Z", attributes: { severity: "high", message: "healthy alert marker" } };
const flow = {
  flowId: "flow-healthy-0001", firstSeen: "2026-10-26T08:00:00Z", lastSeen: "2026-10-26T08:05:00Z",
  srcIp: "10.10.0.22", srcPort: 40110, dstIp: "10.20.0.5", dstPort: 502, transport: "tcp", application: "modbus", eventCount: 3,
};
const template = { name: "healthy-template-marker", description: "Purdue baseline", protocol: "modbus" };
const connection = { proto: "tcp", state: "ESTABLISHED", src: "192.0.2.41", dst: "192.0.2.42", sport: "41001", dport: "502" };

type Trigger = "poll" | "refresh" | "config" | "action";

const transitions: {
  path: string; endpoint: string; healthy: unknown; marker: string; message: string;
  triggers: Trigger[]; pollMs?: number; extra?: Record<string, unknown>;
}[] = [
  { path: "/alerts", endpoint: "/api/v1/events", healthy: [alert], marker: "healthy alert marker", message: "Failed to load alerts.", triggers: ["poll", "refresh"], pollMs: 10_000 },
  { path: "/flows", endpoint: "/api/v1/flows", healthy: [flow], marker: "modbus", message: "Flows unavailable", triggers: ["poll", "refresh"], pollMs: 10_000 },
  { path: "/templates", endpoint: "/api/v1/templates/ics", healthy: [template], marker: "healthy-template-marker", message: "ICS templates unavailable", triggers: ["refresh", "config"] },
  {
    path: "/sessions", endpoint: "/api/v1/conntrack", healthy: [connection], marker: "192.0.2.41", message: "malformed connection list", triggers: ["refresh", "action"],
    extra: {
      "/api/v1/conntrack/kill": {
        scope: "connection", matched: 1, deleted: 1, conntrackDeleted: true, revocationInstalled: true,
        blockedUntil: "2026-10-26T12:00:00Z", closure: "closure not confirmed",
      },
    },
  },
];

for (const t of transitions) {
  for (const trigger of t.triggers) {
    test(`${t.path} reports a malformed ${t.endpoint} after a healthy load (${trigger})`, async ({ page }) => {
      const pageErrors: string[] = [];
      page.on("pageerror", (err) => pageErrors.push(String(err)));
      if (trigger === "poll") await page.clock.install();
      const list = await mockHealthyThenMalformed(page, t.endpoint, { [t.endpoint]: t.healthy, ...t.extra });
      await openHealthy(page, t.path, t.endpoint);
      await expect(page.getByText(t.marker, { exact: false }).first()).toBeVisible();

      const answered = list.breakList();
      if (trigger === "poll") await page.clock.runFor(t.pollMs ?? 0);
      if (trigger === "refresh") await page.getByRole("button", { name: "Refresh", exact: true }).click();
      if (trigger === "config") await committed(page);
      if (trigger === "action") {
        await page.getByRole("button", { name: "Kill", exact: true }).click();
        await page.getByRole("dialog").getByRole("button", { name: "Kill", exact: true }).click();
      }
      await answered;

      await expect(page.getByText(t.message, { exact: false }).first()).toBeVisible();
      await expect(page.getByText(t.marker, { exact: false })).toHaveCount(0);
      expect(pageErrors).toEqual([]);
    });
  }
}

for (const endpoint of ["/api/v1/zones", "/api/v1/security/conduits"]) {
  test(`topology SECURITY view reports malformed ${endpoint} after a healthy load (config)`, async ({ page }) => {
    const pageErrors: string[] = [];
    page.on("pageerror", (err) => pageErrors.push(String(err)));
    const list = await mockHealthyThenMalformed(page, endpoint, {
      "/api/v1/zones": [{ name: "it" }, { name: "ot", slTarget: 2 }],
      "/api/v1/security/conduits": [],
    });
    await page.goto("/topology/");
    const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/security/conduits");
    await page.getByRole("button", { name: "SECURITY", exact: true }).click();
    await loaded;
    await expect(page.getByText("ZONE · CONDUIT MATRIX")).toBeVisible();

    const answered = list.breakList();
    await committed(page);
    await answered;
    await expect(page.getByText("Failed to load security data")).toBeVisible();
    await expect(page.getByText("ZONE · CONDUIT MATRIX")).toHaveCount(0);
    expect(pageErrors).toEqual([]);
  });
}

test("topology PHYSICAL view reports malformed flows after a healthy load (poll)", async ({ page }) => {
  const pageErrors: string[] = [];
  page.on("pageerror", (err) => pageErrors.push(String(err)));
  await page.clock.install();
  const list = await mockHealthyThenMalformed(page, "/api/v1/flows", {
    "/api/v1/config": { zones: [{ name: "it" }], interfaces: [{ name: "lan1", device: "eth0", zone: "it" }] },
  });
  await page.goto("/topology/");
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/flows");
  await page.getByRole("button", { name: "PHYSICAL", exact: true }).click();
  await loaded;
  await expect(page.getByText("Loading inspection data...")).toHaveCount(0);
  await expect(page.getByText("Physical topology unavailable", { exact: false })).toHaveCount(0);

  const answered = list.breakList();
  await page.clock.runFor(30_000);
  await answered;
  await expect(page.getByRole("alert").filter({ hasText: "Physical topology unavailable" })).toBeVisible();
  expect(pageErrors).toEqual([]);
});
