import { expect, test, type Page } from "@playwright/test";
import { observation } from "./fixtures/protection-api";

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

type Mocks = {
  events: unknown[];
  services: unknown;
  health?: unknown;
  eventStats?: unknown;
  stats?: unknown;
  ruleCount?: number;
  ids?: unknown;
  interfaces?: unknown;
  interfaceState?: unknown;
  interfaceCount?: number;
  interfacesStatus?: number;
  interfaceStateStatus?: number;
  simulation?: boolean;
  dashboardStatus?: number;
  protection?: ReturnType<typeof observation>;
};

async function openDashboard(page: Page, mocks: Mocks) {
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const p = new URL(route.request().url()).pathname;
    let body: unknown = {};
    let status = 200;
    if (p === "/api/v1/auth/me" || p === "/api/v1/auth/session") body = user;
    if (p === "/api/v1/dashboard") {
      status = mocks.dashboardStatus ?? 200;
      body = {
        user,
        health: mocks.health ?? { status: "ok", hostname: "test" },
        counts: { assets: 0, zones: zones.length, interfaces: mocks.interfaceCount ?? 0, rules: mocks.ruleCount ?? 0, icsRules: 0 },
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
    if (p === "/api/v1/interfaces") {
      body = "interfaces" in mocks ? mocks.interfaces : [];
      status = mocks.interfacesStatus ?? 200;
    }
    if (p === "/api/v1/interfaces/state") {
      body = "interfaceState" in mocks ? mocks.interfaceState : [];
      status = mocks.interfaceStateStatus ?? 200;
    }
    if (p === "/api/v1/zones") body = zones;
    if (p === "/api/v1/ids/rules") body = mocks.ids ?? { enabled: false, rules: [] };
    if (p === "/api/v1/events") body = mocks.events;
    if (p === "/api/v1/flows") body = flows;
    if (p === "/api/v1/simulation") body = { running: mocks.simulation ?? false };
    if (p === "/api/v1/config/diff") body = { changed: false, changedSections: [], pendingConfirm: null, running: {}, candidate: {} };
    if (p === "/api/v1/dataplane/protection") body = mocks.protection ?? observation();
    if (p === "/api/v1/services/status") body = mocks.services;
    await route.fulfill({ status, json: status === 200 ? body : { error: "telemetry read unavailable" }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
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

const knownServices = {
  ...services,
  vpn: { wireguard_enabled: false, openvpn_running: false },
  proxy: { forward_enabled: false, reverse_enabled: false, envoy_running: false, nginx_running: false },
  syslog: { configured_forwarders: 0, ...meter() },
};

for (const width of [1280, 390]) {
  for (const count of [0, 1, 60]) {
    test(`runtime task count uses plain language and retains its technical title: ${count} at ${width}px`, async ({ page }) => {
      await page.setViewportSize({ width, height: 844 });
      await openDashboard(page, { events: [], services, stats: {
        ruleEval: {}, cpu: { usagePercent: 0 }, memory: { totalBytes: 0, usagePercent: 0 },
        disk: { totalBytes: 0, usagePercent: 0 }, container: { running: true, memUsedBytes: 1024, memLimitBytes: 0, memPercent: 0 },
        runtime: { uptime: "1m", goroutines: count },
      } });
      await expect(page.getByTitle("Go runtime goroutines", { exact: true })).toHaveText(`${count} background task${count === 1 ? "" : "s"}`);
      await expect(page.getByText(`${count} goroutines`, { exact: true })).toHaveCount(0);
    });
  }

  for (const scenario of [
    { name: "zero activity", events: [], services: knownServices, unknown: ["IPS"], alertedZones: [] },
    { name: "single event and zone", events: [idsAlert(1, { srcZone: "lan" })], services: { ...knownServices, proxy: { envoy_running: false } }, unknown: ["IPS", "Proxy"], alertedZones: ["lan"] },
    { name: "multiple events and zones", events: [idsAlert(1, { srcZone: "lan" }), idsAlert(2, { srcZone: "dmz" })], services: null, unknown: ["IPS", "AV", "DNS", "VPN", "Syslog", "Proxy"], alertedZones: ["lan", "dmz"] },
  ]) {
    test(`dashboard panels retain real activity and unknown service states: ${scenario.name} at ${width}px`, async ({ page }) => {
      await page.setViewportSize({ width, height: 844 });
      await openDashboard(page, scenario);
      const servicePanel = page.getByRole("heading", { name: "Service Health", exact: true }).locator("..");
      await expect(servicePanel.getByRole("link").filter({ hasText: "Unknown" })).toHaveCount(scenario.unknown.length);
      for (const name of scenario.unknown) {
        const card = servicePanel.getByRole("link").filter({ has: page.getByText(name, { exact: true }) });
        await expect(card).toBeVisible();
        await expect(card).toContainText("Unknown");
        await expect(card).not.toHaveClass(/border-emerald/);
      }
      const stream = page.getByRole("heading", { name: "Event Stream", exact: true }).locator("..");
      await expect(stream.getByText("test alert", { exact: true })).toHaveCount(scenario.events.length);
      if (!scenario.events.length) await expect(stream.getByText("No events yet", { exact: true })).toBeVisible();
      for (const zone of zones) {
        const card = zoneCard(page, zone.name);
        await expect(card).toBeVisible();
        if (scenario.alertedZones.some(name => name === zone.name)) await expect(card).toContainText("1 alert");
        else {
          await expect(card).toContainText("CLEAR");
          await expect(card).not.toContainText(/alert/);
        }
      }
    });
  }
}

// Counts pixels close to the alert red the canvas uses for critical zones.
function redPixels(page: Page) {
  return page.getByRole("heading", { name: "Network Pulse", exact: true }).locator("../..").locator("canvas").first().evaluate((canvas: HTMLCanvasElement) => {
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
  const canvas = page.getByRole("heading", { name: "Network Pulse", exact: true }).locator("../..").locator("canvas").first();
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

for (const scenario of [
  { name: "unavailable scanner", status: { ...services, av: { available: false, error: "engine unavailable" } }, message: "AV: Scanner unavailable" },
  { name: "stopped DNS", status: { ...services, dns: { enabled: true, running: false } }, message: "DNS: Stopped" },
  { name: "stopped proxy", status: { ...services, proxy: { forward_enabled: true, reverse_enabled: false, envoy_running: false, nginx_running: false } }, message: "Proxy: Stopped" },
  { name: "syslog errors", status: { ...services, syslog: { configured_forwarders: 1, ...meter(), errors_rate_per_min: 2 } }, message: "Syslog: 1 fwd · 0/min · 2.0 err/min" },
]) {
  test(`service attention stays visible on load: ${scenario.name}`, async ({ page }) => {
    await openDashboard(page, { events: [], services: scenario.status });
    const attention = page.getByRole("status").filter({ hasText: scenario.message });
    await expect(attention).toBeVisible();
    await expect(attention.getByRole("link", { name: "Check service" })).toBeVisible();
  });
}

test("service attention uses runtime state, not service display text", async ({ page }) => {
  await openDashboard(page, { events: [], services: {
    ...services, av: { ...services.av, mode: "Stopped" },
    dns: { enabled: false, running: false }, proxy: { envoy_running: false },
    syslog: { configured_forwarders: 0, ...meter() },
  } });
  const av = page.locator("a.rounded-lg").filter({ has: page.getByText("AV", { exact: true }) });
  await expect(av).toContainText("Stopped");
  await expect(av).toHaveClass(/border-emerald/);
  await expect(page.getByRole("link", { name: "Check service", exact: true })).toHaveCount(0);
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

const bindStep = (page: Page) => page.locator("#setup-checklist").getByText("Bind interfaces", { exact: true }).locator("../..");
const device = (name: string) => ({ name, index: 1, up: true, mtu: 1500, mac: "02:00:00:00:00:01", addrs: [] });

for (const scenario of [
  { name: "unbound logical records", interfaces: [{ name: "lo" }, { name: "lan" }], interfaceState: [device("lo"), device("eth0")], ready: false },
  { name: "partially bound records", interfaces: [{ name: "lan", device: "eth0" }, { name: "wan" }], interfaceState: [device("eth0"), device("eth1")], ready: false },
  { name: "missing device with no spare device", interfaces: [{ name: "lan", device: "absent0" }], interfaceState: [device("lo")], ready: false },
  { name: "explicit device binding", interfaces: [{ name: "lan", device: "eth0" }], interfaceState: [device("eth0")], ready: true },
  { name: "bound device with its link down", interfaces: [{ name: "lan", device: "eth0" }], interfaceState: [{ ...device("eth0"), up: false }], ready: true },
  { name: "matching logical and device name", interfaces: [{ name: "eth0" }], interfaceState: [device("eth0")], ready: true },
  { name: "no reported network devices", interfaces: [{ name: "lan", device: "eth0" }], interfaceState: [], ready: false },
  { name: "no configured interfaces", interfaces: [], interfaceState: [device("eth0")], ready: false },
]) {
  test(`Bind interfaces readiness follows Interfaces device matching: ${scenario.name}`, async ({ page }) => {
    await openDashboard(page, { events: [], services, interfaceCount: scenario.interfaces.length, ...scenario });
    await expect(bindStep(page).getByText(scenario.ready ? "Ready" : "Action", { exact: true })).toBeVisible();
    await expect(bindStep(page).getByText(scenario.ready ? "Action" : "Ready", { exact: true })).toHaveCount(0);
    if (scenario.ready) await expect(bindStep(page)).toContainText("1 of 1 bound to network devices");
    else if (scenario.interfaces.length) await expect(bindStep(page)).toContainText("not connected to network devices");
  });
}

for (const failure of [
  { name: "configuration HTTP failure", interfacesStatus: 503 },
  { name: "runtime HTTP failure", interfaceStateStatus: 503 },
  { name: "configuration null", interfaces: null },
  { name: "runtime null", interfaceState: null },
]) {
  test(`Bind interfaces stays unknown with ${failure.name}`, async ({ page }) => {
    await openDashboard(page, { events: [], services, interfaceCount: 1,
      interfaces: [{ name: "lan", device: "eth0" }], interfaceState: [device("eth0")], ...failure,
    });
    await expect(bindStep(page).getByText("Unknown", { exact: true })).toBeVisible();
    await expect(bindStep(page).getByText("Ready", { exact: true })).toHaveCount(0);
    await expect(bindStep(page)).toContainText("Interface bindings unknown");
  });
}

test("Bind interfaces discards stale readiness on a failed refresh and recovers", async ({ page }) => {
  await page.clock.install();
  const mocks: Mocks = { events: [], services, interfaceCount: 1,
    interfaces: [{ name: "lan", device: "eth0" }], interfaceState: [device("eth0")],
  };
  await openDashboard(page, mocks);
  await expect(bindStep(page).getByText("Ready", { exact: true })).toBeVisible();
  mocks.interfaceStateStatus = 503;
  await page.clock.fastForward(10_000);
  await expect(bindStep(page).getByText("Unknown", { exact: true })).toBeVisible();
  await expect(bindStep(page).getByText("Ready", { exact: true })).toHaveCount(0);
  mocks.interfaceStateStatus = 200;
  await page.clock.fastForward(10_000);
  await expect(bindStep(page).getByText("Ready", { exact: true })).toBeVisible();
});


test("a completed checklist keeps every task visible without a collapse control", async ({ page }) => {
  await openDashboard(page, { events: [], services, ruleCount: 1, interfaceCount: 1,
    interfaces: [{ name: "lan", device: "eth0" }], interfaceState: [device("eth0")],
  });
  await expect(page.getByRole("heading", { name: "First-Run Checklist", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: /^First-Run Checklist/ })).toHaveCount(0);
  for (const task of ["Create zones", "Bind interfaces", "Create policy", "Commit runtime changes"]) {
    const card = page.locator("#setup-checklist").getByText(task, { exact: true }).locator("../..");
    await expect(card).toBeVisible();
    await expect(card.getByText("Ready", { exact: true })).toBeVisible();
  }
});

test("active simulation is visible in the header and Stop acts immediately", async ({ page }) => {
  await openDashboard(page, { events: [], services, simulation: true });
  const stop = page.getByTitle("Stop traffic simulation");
  await expect(stop).toBeVisible();
  await expect(stop).toContainText("SIM");
  await page.route("**/api/v1/simulation", async (route) => {
    expect(route.request().method()).toBe("POST");
    expect(route.request().postDataJSON()).toEqual({ action: "stop" });
    await route.fulfill({ json: { running: false }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  await stop.click();
  await expect(page.getByTitle("Start traffic simulation")).toBeVisible();
  await expect(stop).toHaveCount(0);
  await expect(page.getByRole("button", { name: "CLI Console", exact: true })).toBeVisible();
});

const panelHeadings = ["Network Pulse", "Zone Status", "Service Health", "Traffic", "Event Stream", "System Health"];

test("all six dashboard panels and the SIM toggle are visible on load without any click", async ({ page }) => {
  await openDashboard(page, { events: [], services });
  for (const heading of panelHeadings) {
    await expect(page.getByRole("heading", { name: heading === "Traffic" ? "Traffic60s window" : heading, exact: true })).toBeVisible();
  }
  await expect(page.getByTitle("Start traffic simulation")).toBeVisible();
  await expect(page.getByRole("button", { name: /^Dashboard details$|^Tools$/ })).toHaveCount(0);
});

test("stale dashboard totals are discarded while failed enforcement remains prominent", async ({ page }) => {
  await page.clock.install();
  const mocks: Mocks = { events: [], services, protection: observation({ state: "failed",
    components: [{ name: "nft", required: true, state: "failed", reason: "apply rejected", since: "2026-10-31T12:00:00Z" }],
    effects: [{ traffic: "Monitor traffic", effect: "not_inspected" }],
  }) };
  await openDashboard(page, mocks);
  const protection = page.getByRole("status", { name: "Traffic protection" });
  await expect(protection).toContainText("apply rejected");
  mocks.dashboardStatus = 503;
  await page.clock.fastForward(10_000);
  await expect(page.getByRole("alert").filter({ hasText: /Dashboard unavailable/ })).toBeVisible();
  await expect(page.getByText("No recent IDS/AV alerts", { exact: true })).toHaveCount(0);
  const counter = page.getByText("Total Events", { exact: true }).locator("..");
  await expect(counter).toContainText("Unknown");
  await expect(protection).toBeVisible();
  await expect(protection).toContainText("Monitor traffic is not being inspected");
});


test("all dashboard panels stay within a 390px viewport", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await openDashboard(page, { events: [idsAlert(1)], services, simulation: true });
  for (const heading of panelHeadings) {
    await expect(page.getByRole("heading", { name: heading === "Traffic" ? "Traffic60s window" : heading, exact: true })).toBeVisible();
  }
  await expect(page.getByTitle("Stop traffic simulation")).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
});
