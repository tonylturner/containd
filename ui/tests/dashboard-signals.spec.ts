import { expect, test, type Page } from "@playwright/test";

// The dashboard shows only what the APIs report: no animated traffic, no
// invented baseline, and no alert pinned to a zone the event does not name.

const user = { id: "admin-1", username: "containd", role: "admin", mfaRequired: false };
const zones = [{ name: "lan" }, { name: "dmz" }, { name: "ot" }];

function meter(sparkline: number[] = []) {
  return {
    sparkline,
    count: sparkline.reduce((a, b) => a + b, 0),
    rate_per_min: 0,
    errors_sparkline: [],
    errors_count: 0,
    errors_rate_per_min: 0,
  };
}

function idsAlert(id: number, eventAttrs?: Record<string, unknown>) {
  return {
    id,
    flowId: `flow-${id}`,
    proto: "ids",
    kind: "alert",
    timestamp: new Date().toISOString(),
    attributes: { rule_id: "r1", message: "test alert", ...(eventAttrs ? { event_attrs: eventAttrs } : {}) },
  };
}

// Enough recent flows that the old canvas spawned a packet every few frames.
const flows = Array.from({ length: 60 }, (_, i) => ({
  flowId: `flow-${i}`,
  firstSeen: new Date().toISOString(),
  lastSeen: new Date().toISOString(),
  eventCount: 1,
}));

type Mocks = { events: unknown[]; services: unknown; health?: unknown; eventStats?: unknown; stats?: unknown; ruleCount?: number; ids?: unknown };

async function openDashboard(page: Page, mocks: Mocks) {
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const p = new URL(route.request().url()).pathname;
    let body: unknown = {};
    if (p === "/api/v1/auth/me" || p === "/api/v1/auth/session") body = user;
    if (p === "/api/v1/dashboard") {
      body = {
        user,
        health: mocks.health ?? { status: "ok", hostname: "test" },
        counts: { assets: 0, zones: zones.length, interfaces: 0, rules: mocks.ruleCount ?? 0, icsRules: 0 },
        eventStats: "eventStats" in mocks ? mocks.eventStats : { total: mocks.events.length, idsAlerts: 0, modbusWrites: 0, avDetections: 0, avBlocks: 0 },
        services: null,
        lastActivity: null,
      };
    }
    if (p === "/api/v1/system/stats") {
      body = mocks.stats ?? {
        ruleEval: {}, cpu: { usagePercent: 0 }, memory: { totalBytes: 0, usagePercent: 0 },
        disk: { totalBytes: 0, usagePercent: 0 }, container: { running: true, memUsedBytes: 1024, memLimitBytes: 0, memPercent: 0 },
        runtime: { uptime: "1m", goroutines: 1 },
      };
    }
    if (p === "/api/v1/zones") body = zones;
    if (p === "/api/v1/ids/rules") body = mocks.ids ?? { enabled: false, rules: [] };
    if (p === "/api/v1/events") body = mocks.events;
    if (p === "/api/v1/flows") body = flows;
    if (p === "/api/v1/simulation") body = { running: false };
    if (p === "/api/v1/config/diff") body = { running: {}, candidate: {} };
    if (p === "/api/v1/services/status") body = mocks.services;
    await route.fulfill({ json: body, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  const loaded = Promise.all(["/api/v1/events", "/api/v1/zones", "/api/v1/flows", "/api/v1/system/stats"].map(
    (path) => page.waitForResponse((r) => new URL(r.url()).pathname === path),
  ));
  await page.goto("/");
  await loaded;
}

const zoneCard = (page: Page, name: string) => page.locator("a[href='/zones/']").filter({ hasText: name });

const services = {
  faults: [],
  dns: { enabled: true, running: true, ...meter([1, 0, 2]) },
  av: { available: true, enabled: true, mode: "clamav", ...meter([3, 1]) },
};

// Counts pixels close to the alert red the canvas uses for critical zones.
function redPixels(page: Page) {
  return page.locator("canvas").first().evaluate((canvas: HTMLCanvasElement) => {
    const ctx = canvas.getContext("2d")!;
    const { data } = ctx.getImageData(0, 0, canvas.width, canvas.height);
    let red = 0;
    for (let i = 0; i < data.length; i += 4) {
      if (data[i] > 200 && data[i + 1] < 110 && data[i + 2] < 110 && data[i + 3] > 200) red++;
    }
    return red;
  });
}

test("network pulse is a still picture of real zone state", async ({ page }) => {
  await openDashboard(page, { events: [idsAlert(1)], services });
  const canvas = page.locator("canvas").first();
  await expect(zoneCard(page, "lan")).toContainText("CLEAR");
  const first = await canvas.screenshot();
  await page.waitForTimeout(750);
  expect((await canvas.screenshot()).equals(first)).toBe(true);
  // An alert that names no zone colours no zone.
  expect(await redPixels(page)).toBe(0);
});

test("only alerts that name a zone mark it", async ({ page }) => {
  const lanAlerts = Array.from({ length: 5 }, (_, i) => idsAlert(10 + i, { srcZone: "lan" }));
  await openDashboard(page, { events: [idsAlert(1), ...lanAlerts], services });
  await expect(zoneCard(page, "lan")).toContainText("CRITICAL");
  await expect(zoneCard(page, "lan")).toContainText("5 alerts");
  for (const name of ["dmz", "ot"]) {
    await expect(zoneCard(page, name)).toContainText("CLEAR");
    await expect(zoneCard(page, name)).not.toContainText("alert");
  }
  expect(await redPixels(page)).toBeGreaterThan(0);
});

test("a quiet traffic window draws no invented baseline", async ({ page }) => {
  await openDashboard(page, { events: [], services });
  await expect(page.getByText("60s window", { exact: true })).toBeVisible();
  await expect(page.getByText("24h baseline")).toHaveCount(0);
});

test("service cards read the services status, antivirus included", async ({ page }) => {
  await openDashboard(page, { events: [], services });
  const card = (name: string) => page.locator("a.rounded-lg").filter({ has: page.getByText(name, { exact: true }) });
  await expect(card("AV")).toContainText("clamav");
  await expect(card("DNS")).toContainText("Resolving");

  await page.unrouteAll({ behavior: "wait" });
  await openDashboard(page, { events: [], services: { faults: [], av: { available: false, error: "engine unavailable" } } });
  await expect(card("AV")).toContainText("Scanner unavailable");
  await expect(card("DNS")).toContainText("Unknown");
});

test("partially reported service entries do not claim stopped or disabled", async ({ page }) => {
  await openDashboard(page, { events: [], services: {
    faults: [], av: { available: true }, vpn: { wireguard_enabled: false }, proxy: { envoy_running: false },
  } });
  for (const name of ["AV", "DNS", "VPN", "Syslog", "Proxy"]) {
    const card = page.locator("a.rounded-lg").filter({ has: page.getByText(name, { exact: true }) });
    await expect(card).toContainText("Unknown");
    await expect(card).not.toContainText(/Disabled|Stopped|No tunnels/);
  }
});


test("a quiet alert window does not claim overall health when protection is degraded", async ({ page }) => {
  await openDashboard(page, { events: [], services, health: { hostname: "test", status: "degraded", enforceEnabled: false } });
  await expect(page.getByText("No recent IDS/AV alerts", { exact: true })).toBeVisible();
  await expect(page.getByText("All systems nominal", { exact: true })).toHaveCount(0);
});

test("missing dashboard alert counts remain unknown", async ({ page }) => {
  await openDashboard(page, { events: [], services, eventStats: {} });
  await expect(page.getByText("Recent IDS/AV alerts unavailable", { exact: true })).toBeVisible();
  await expect(page.getByText("No recent IDS/AV alerts", { exact: true })).toHaveCount(0);
});


test("rule counts and unknown container memory do not fabricate utilization bars", async ({ page }) => {
  await openDashboard(page, { events: [], services, ruleCount: 60 });
  const ruleRow = page.getByText("Rule Eval", { exact: true }).locator("../..");
  await expect(ruleRow).toContainText("60 rules");
  await expect(ruleRow.locator("[style*='width']")).toHaveCount(0);
  const containerRow = page.getByText("Container", { exact: true }).locator("../..");
  await expect(containerRow).toContainText("Running");
  await expect(containerRow.locator("[style*='width']")).toHaveCount(0);
});

test("a measured zero container memory stays zero, not a synthetic minimum", async ({ page }) => {
  await openDashboard(page, { events: [], services, stats: {
    ruleEval: {}, cpu: { usagePercent: 0 }, memory: { totalBytes: 0, usagePercent: 0 },
    disk: { totalBytes: 0, usagePercent: 0 }, container: { running: true, memUsedBytes: 0, memLimitBytes: 1048576, memPercent: 0 },
    runtime: { uptime: "1m", goroutines: 1 },
  } });
  const containerRow = page.getByText("Container", { exact: true }).locator("../..");
  await expect(containerRow.locator("[style*='width']")).toHaveAttribute("style", /width: 0%;/);
});

for (const ids of [{ enabled: false, rules: [] }, { enabled: true, rules: [] }]) {
  test(`IPS is unknown without a live protection observation, even with IDS enabled=${ids.enabled}`, async ({ page }) => {
    await openDashboard(page, { events: [], services, ids });
    const ips = page.locator("a.rounded-lg").filter({ has: page.getByText("IPS", { exact: true }) });
    await expect(ips).toContainText("Unknown");
    await expect(ips).not.toContainText("Active");
    await expect(ips).not.toHaveClass(/border-emerald/);
  });
}

for (const forward_enabled of [false, true]) {
  test(`proxy distinguishes disabled from stopped with forward enabled=${forward_enabled}`, async ({ page }) => {
    await openDashboard(page, { events: [], services: { ...services,
      proxy: { forward_enabled, reverse_enabled: false, envoy_running: false, nginx_running: false },
    } });
    const proxy = page.locator("a.rounded-lg").filter({ has: page.getByText("Proxy", { exact: true }) });
    await expect(proxy).toContainText(forward_enabled ? "Stopped" : "Disabled");
    const unknown = page.locator("a.rounded-lg").filter({ has: page.getByText("IPS", { exact: true }) });
    await expect(unknown).toContainText("Unknown");
    await expect(unknown).not.toHaveClass(/opacity-50|border-emerald/);
    await expect(proxy).toHaveClass(/opacity-50/);
  });
}
