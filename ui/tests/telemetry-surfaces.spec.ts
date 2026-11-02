import { expect, test, type Page } from "@playwright/test";
import { CONFIG_COMMITTED } from "../lib/config-events";
import type { Conduit, TelemetryEvent } from "../lib/api";
import { observation } from "./fixtures/protection-api";
import { seriesResponse, type WireResponse } from "./fixtures/telemetry";

const demoEvent: TelemetryEvent = { id: "9007199254740993", flowId: "f1", proto: "ids", kind: "alert", origin: "demo", timestamp: "2026-11-02T12:00:00Z", attributes: { message: "Demo alert" } };
type Scenario = { eventsFailed?: boolean; totalsFailed?: boolean; conduit?: Conduit["traffic"]; mutate?: (body: WireResponse, url: URL) => void; conduitsFailed?: boolean; reverseBytes?: string };
async function open(page: Page, path: string, scenario: Scenario = {}) {
  const requests: URL[] = [];
  const config = { zones: [{ name: "it", slTarget: 1 }, { name: "ot", slTarget: 2 }], interfaces: [{ name: "lan", device: "eth9", zone: "it", addresses: ["192.0.2.1/24"] }], routing: { gateways: [], routes: [], rules: [] }, firewall: { rules: [] } };
  const conduit: Conduit = { from: "it", to: "ot", state: "allow", ids: "none", proto: [], rules: [], gaps: [], mitre: [], defaultDeny: true, tlsEnforced: false, protoWhitelist: false, mfaRequired: false, auditLogged: false, avEnabled: false,
    traffic: { state: "measured", windowSeconds: 3600, bytes: "9007199254740993", packets: "25", complete: false, coverage: "routed" } };
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async route => {
    const url = new URL(route.request().url());
    const p = url.pathname;
    const user = { id: "admin", username: "admin", role: "admin" };
    let body: unknown = {};
    let status = 200;
    if (p.includes("/auth/")) body = user;
    if (p === "/api/v1/telemetry/series") {
      requests.push(url);
      const data = seriesResponse(url, url.searchParams.get("metric") === "service.errors" ? [0, 0, 0] : [10, 0, 20]);
      scenario.mutate?.(data, url);
      body = data;
    }
    if (p === "/api/v1/dashboard") body = { user, counts: { assets: 0, zones: 2, interfaces: 1, rules: 1, icsRules: 0 }, health: { hostname: "test" },
      eventStats: scenario.totalsFailed ? null : { windowSeconds: 86400, complete: false, total: 12, idsAlerts: 0, modbusWrites: 0, avDetections: 0, avBlocks: 0 },
      ...(scenario.totalsFailed ? { eventStatsError: "store read failed" } : {}) };
    if (p === "/api/v1/system/stats") body = { ruleEval: {}, cpu: { usagePercent: 0 }, memory: { totalBytes: 0, usagePercent: 0 }, disk: { totalBytes: 0, usagePercent: 0 }, container: { running: true, memLimitBytes: 0 }, runtime: { uptime: "1m", goroutines: 1 } };
    if (p === "/api/v1/events") {
      status = scenario.eventsFailed ? 503 : 200;
      body = url.searchParams.has("query") ? { events: [demoEvent], historyTruncated: false } : [demoEvent];
    }
    if (p === `/api/v1/events/${demoEvent.id}`) body = demoEvent;
    if (p === "/api/v1/flows") body = [{ flowId: "f1", srcIp: "192.0.2.2", dstIp: "198.51.100.2", eventCount: 99999 }];
    if (p === "/api/v1/config" || p === "/api/v1/config/running") body = config;
    if (p === "/api/v1/config/diff") body = { changed: false, running: {}, candidate: {} };
    if (p === "/api/v1/zones") body = config.zones;
    if (p === "/api/v1/interfaces") body = config.interfaces;
    if (p === "/api/v1/interfaces/state") body = [{ name: "eth9", up: true, addrs: ["192.0.2.1/24"] }];
    if (p === "/api/v1/routing/os") body = { routes: [] };
    if (p === "/api/v1/simulation") body = { running: false };
    if (p === "/api/v1/health") body = { status: "ok", enforcement: { state: "disabled" } };
    if (p === "/api/v1/dataplane/protection") body = observation();
    if (p === "/api/v1/services/status") body = { faults: [], av: { available: false, error: "scanner offline" } };
    if (p === "/api/v1/security/conduits") {
      body = [{ ...conduit, traffic: scenario.conduit ?? conduit.traffic }, ...(scenario.reverseBytes === undefined ? [] : [{
        ...conduit, from: "ot", to: "it", traffic: { state: "measured", windowSeconds: 3600, bytes: scenario.reverseBytes, packets: "2", complete: true, coverage: "routed" },
      }])];
      status = scenario.conduitsFailed ? 503 : 200;
    }
    await route.fulfill({ status, json: status === 200 ? body : { error: "read failed" }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  await page.goto(path);
  return requests;
}

for (const width of [1280, 390]) {
  test(`dashboard keeps six panels and measures In/Out, zones and events at ${width}px`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 844 });
    const requests = await open(page, "/", { mutate: body => {
      if (body.metric === "events.total") body.series.push({ dims: { source: "services" }, points: body.series[0].points.map(p => ({ ...p })) });
    } });
    for (const title of ["Network Pulse", "Zone Status", "Service Health", "Traffic", "Event Stream", "System Health"]) await expect(page.getByRole("heading", { name: new RegExp(`^${title}(1h window)?$`) })).toBeVisible();
    for (const title of ["In bytes/s", "Out bytes/s"]) await expect(page.locator(`[data-telemetry="${title}"]`)).toContainText("Rate: 2.0 /s");
    await expect(page.locator('[data-telemetry="Events"]')).toContainText("Rate: 4.0 /s");
    await expect(page.locator("[data-telemetry-legend]")).toHaveCount(1);
    await expect(page.getByText("Trend:", { exact: false })).toHaveCount(0);
    expect(requests.some(q => q.searchParams.get("metric") === "iface.rx_bytes" && q.searchParams.get("role") === "leaf" && q.searchParams.get("group") === "role")).toBe(true);
    await expect(page.getByText("in + out at this zone · bytes/s", { exact: true })).toHaveCount(2);
    await expect(page.locator('[data-telemetry="it throughput"] [data-value="40"]')).toHaveCount(1);
    await expect(page.getByText("Event totals: last 24 h · Partial coverage", { exact: true })).toBeVisible();
    await expect(page.getByText("IDS/AV alerts: partial 24h coverage", { exact: true })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Event Stream", exact: true }).locator("..").getByText("Demo", { exact: true })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    if (width === 390) await page.screenshot({ path: testInfo.outputPath("dashboard-telemetry-390.png"), fullPage: true });
  });
}

for (const metadata of [false, true]) {
  test(`an engine member gap plus covered services zero cannot hide behind retained Events demo (metadata=${metadata})`, async ({ page }) => {
    await page.clock.install();
    let outage = false;
    const requests = await open(page, "/", { mutate: (body, url) => {
      if (body.metric !== "events.total") return;
      body.realActive = false;
      if (body.origin === "demo") {
        body.series = seriesResponse(url, outage ? [5, 5, null] : [5, 5, 5]).series;
        body.series[0].dims = { source: "engine" };
        return;
      }
      const engine = seriesResponse(url, outage ? [0, 0, null] : [0, 0, 0]).series[0];
      engine.dims = { source: "engine" };
      const services = seriesResponse(url, [0, 0, 0]).series[0];
      services.dims = { source: "services" };
      body.series = [engine, services];
      if (outage && metadata) body.collector.unavailable = [{ source: "engine", reason: "engine connection refused" }];
    } });
    const events = page.locator('[data-telemetry="Events"]');
    await expect(events.getByText("Demo data", { exact: true })).toBeVisible();
    const demoReads = requests.filter(url => url.searchParams.get("origin") === "demo").length;
    outage = true;
    await page.clock.fastForward(10_000);
    await expect(events).toContainText(metadata ? "Telemetry unavailable: engine connection refused" : "Telemetry unavailable: latest real bucket is a gap");
    await expect(events.getByText("Demo data", { exact: true })).toHaveCount(0);
    expect(requests.filter(url => url.searchParams.get("origin") === "demo")).toHaveLength(demoReads);
    if (metadata) {
      await expect(events.getByRole("img")).toBeVisible();
      await expect(events.locator('[data-quality="partial"][data-value="0"]')).toHaveCount(1);
    }
    outage = false;
    await page.clock.fastForward(10_000);
    await expect(events.getByText("Demo data", { exact: true })).toBeVisible();
    await expect(events.getByRole("status")).toHaveCount(0);
  });
}

test("any unavailable real response prevents demo for a multi-metric zone chart", async ({ page }) => {
  await open(page, "/", { mutate: (body, url) => {
    if (!body.metric.startsWith("iface.") || url.searchParams.get("group") !== "zone") return;
    body.realActive = false;
    body.series = seriesResponse(url, body.origin === "real" ? [0, 0, 0] : [10, 10, 10]).series;
    if (body.origin === "real" && body.metric === "iface.tx_bytes") {
      body.collector.unavailable = [{ source: "iface", reason: "interface eth9 missing" }];
    }
  } });
  const zone = page.locator('[data-telemetry="it throughput"]');
  await expect(zone.getByRole("status")).toHaveText("Telemetry unavailable: interface eth9 missing");
  await expect(zone.getByText("Demo data", { exact: true })).toHaveCount(0);
  await expect(zone.getByRole("img")).toBeVisible();
});

test("an active real metric still shows partial member coverage without demo", async ({ page }) => {
  await open(page, "/", { mutate: (body, url) => {
    if (body.metric !== "events.total") return;
    const engine = seriesResponse(url, [10, 0, null]).series[0];
    engine.dims = { source: "engine" };
    const services = seriesResponse(url, [0, 0, 20]).series[0];
    services.dims = { source: "services" };
    body.series = [engine, services];
  } });
  const events = page.locator('[data-telemetry="Events"]');
  await expect(events).toContainText("Rate: 2.0 /s");
  await expect(events.locator('[data-quality="partial"][data-value="20"]')).toHaveCount(1);
  await expect(events.getByText("Demo data", { exact: true })).toHaveCount(0);
});

test("failed event reads leave Dashboard totals and stream unknown, but independent interface telemetry remains", async ({ page }) => {
  await open(page, "/", { eventsFailed: true, totalsFailed: true });
  await expect(page.getByRole("alert").filter({ hasText: "Recent events unavailable" })).toBeVisible();
  await expect(page.getByText("Total Events", { exact: true }).locator("..")).toContainText("Unknown");
  await expect(page.getByText("Event totals unavailable: store read failed", { exact: true })).toBeVisible();
  await expect(page.locator('[data-telemetry="In bytes/s"]')).toContainText("Rate: 2.0 /s");
  await expect(page.locator('[data-telemetry="it throughput"]').getByRole("img")).toBeVisible();
  await expect(page.getByText("No events yet", { exact: true })).toHaveCount(0);
});

test("grouped counts without a common duration stay partial without fabricated rates at 390px", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await open(page, "/", { mutate: (body, url) => {
    const last = body.series[0].points.at(-1)!;
    if (body.metric === "iface.rx_bytes" && url.searchParams.get("group") === "role") {
      last.q = "partial";
      last.v = "9007199254740993";
      delete last.d;
    }
    if (body.metric === "iface.tx_bytes" && url.searchParams.get("group") === "zone") {
      last.q = "partial";
      last.d = 20;
    }
  } });
  const incoming = page.locator('[data-telemetry="In bytes/s"]');
  await expect(incoming).toContainText("Count: 9,007,199,254,740,993 · Partial bucket — rate unavailable");
  await expect(incoming).toContainText("Rate: Unknown /s");
  const point = incoming.locator('[data-quality="partial"]');
  await expect(point).toHaveAttribute("aria-label", /9007199254740993 counts; duration unavailable; rate unavailable; Partial bucket/);
  await expect(point.locator("[data-bar]")).toHaveCount(0);
  await expect(point.locator("[data-count-only]")).toHaveCSS("border-top-style", "dashed");
  const zone = page.locator('[data-telemetry="it throughput"]');
  await expect(zone).toContainText("Count: 40 · Partial bucket — rate unavailable");
  await expect(zone.locator('[data-quality="partial"] [data-bar]')).toHaveCount(0);
  await expect(page.locator('[data-telemetry="Out bytes/s"]')).toContainText("Rate: 2.0 /s");
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
});

test("Monitoring protocol totals and Traffic Pulse use retained packet and interface counters, not IDS events", async ({ page }) => {
  await open(page, "/monitoring/");
  const protocols = page.getByRole("region", { name: "Top Protocols", exact: true });
  await expect(protocols).toContainText("modbus");
  await expect(protocols).toContainText("30 · Partial coverage");
  await expect(protocols).not.toContainText("ids");
  await expect(page.getByRole("region", { name: "Traffic Pulse", exact: true })).toContainText("Rate: 2.0 /s");
  await expect(page.locator("[data-telemetry-legend]")).toHaveCount(1);
  await expect(page.getByText("Trend:", { exact: false })).toHaveCount(0);
  await expect(page.getByRole("region", { name: "Recent Alerts", exact: true }).getByText("Demo", { exact: true })).toBeVisible();
});

test("Monitoring failed event reads do not appear as zero events, zero alerts, or No alerts", async ({ page }) => {
  await open(page, "/monitoring/", { eventsFailed: true });
  for (const title of ["DPI Events", "IDS Alerts"]) {
    const tile = page.getByRole("region", { name: title, exact: true });
    await expect(tile).toContainText("Unavailable");
    await expect(tile.getByText("0", { exact: true })).toHaveCount(0);
  }
  await expect(page.getByRole("region", { name: "Recent Alerts", exact: true })).toContainText("Recent events unavailable — alert counts unknown.");
  await expect(page.getByText("No alerts.", { exact: true })).toHaveCount(0);
});

test("event list, inspection and loaded event detail retain the Demo badge", async ({ page }) => {
  await open(page, "/events/");
  await expect(page.getByText("Demo", { exact: true }).filter({ visible: true })).toHaveCount(1);
  await page.getByRole("button", { name: "Inspect event", exact: true }).click();
  await expect(page.locator(`#event-inspection-${demoEvent.id}`).getByText("Demo", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: `Event ${demoEvent.id}`, exact: true }).click();
  await expect(page.getByText("Event JSON", { exact: false }).getByText("Demo", { exact: true })).toBeVisible();
});

for (const measured of [true, false]) {
  test(`conduit ${measured ? "measured" : "unavailable"} is explicit and never a percent of baseline`, async ({ page }) => {
    await open(page, "/topology/", measured ? {} : { conduit: { state: "unavailable", reason: "accounting table missing" } });
    await page.getByRole("button", { name: "SECURITY", exact: true }).click();
    await page.getByRole("button", { name: "Inspect IT to OT", exact: true }).click();
    const inspector = page.getByRole("region", { name: "Conduit details", exact: true });
    await expect(inspector).toContainText("routed traffic that passed policy, last hour");
    await expect(inspector).toContainText(measured ? "9,007,199,254,740,993 bytes · 25 packets · Partial coverage" : "Unavailable: accounting table missing");
    await expect(inspector).not.toContainText(/baseline|Live/);
  });
}

test("failed conduit refresh discards stale measurements", async ({ page }) => {
  const scenario: Scenario = {};
  await open(page, "/topology/", scenario);
  await page.getByRole("button", { name: "SECURITY", exact: true }).click();
  await page.getByRole("button", { name: "Inspect IT to OT", exact: true }).click();
  const inspector = page.getByRole("region", { name: "Conduit details", exact: true });
  await expect(inspector).toContainText("9,007,199,254,740,993 bytes");
  scenario.conduitsFailed = true;
  await page.evaluate(event => window.dispatchEvent(new CustomEvent(event)), CONFIG_COMMITTED);
  await expect(page.getByText("9,007,199,254,740,993 bytes", { exact: false })).toHaveCount(0);
  await expect(inspector).toHaveCount(0);
  await expect(page.getByText(/Failed to load security data/)).toBeVisible();
});

test("logical interface RX/TX use measured latest buckets instead of eventCount estimates", async ({ page }) => {
  const requests = await open(page, "/topology/");
  await page.locator('.react-flow__node[data-id="fw-main"]').click();
  const inspector = page.getByRole("region", { name: "Topology inspector", exact: true });
  await expect(inspector).toContainText("RX 2.0 /s packets");
  await expect(inspector).toContainText("TX 2.0 /s packets");
  await expect(inspector).not.toContainText("99999");
  expect(requests.some(q => q.searchParams.get("metric") === "iface.rx_packets" && q.searchParams.get("interface") === "eth9")).toBe(true);
});


test("conduit heat is relative to the largest measured byte count and observed zero has no floor at 390px", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const scenario: Scenario = { conduit: { state: "measured", windowSeconds: 3600, bytes: "100", packets: "1", complete: true, coverage: "routed" }, reverseBytes: "200" };
  await open(page, "/topology/", scenario);
  await page.getByRole("button", { name: "SECURITY", exact: true }).click();
  const cell = page.getByRole("button", { name: "Inspect IT to OT", exact: true });
  await expect(cell.getByTitle("100 bytes · 1 packets", { exact: true })).toHaveCSS("opacity", "0.5");
  await expect(page.getByRole("button", { name: "Inspect OT to IT", exact: true }).getByTitle("200 bytes · 2 packets", { exact: true })).toHaveCSS("opacity", "1");
  scenario.conduit = { ...scenario.conduit as Extract<Conduit["traffic"], { state: "measured" }>, bytes: "0", packets: "0" };
  await page.evaluate(event => window.dispatchEvent(new CustomEvent(event)), CONFIG_COMMITTED);
  await expect(cell.getByTitle("0 bytes · 0 packets", { exact: true })).toHaveCSS("opacity", "0");
  await cell.click();
  await expect(page.getByRole("region", { name: "Conduit details", exact: true })).toContainText("0 bytes · 0 packets");
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
});

test("logical interface unknown coverage is not shown as zero packets", async ({ page }) => {
  await open(page, "/topology/", { mutate: body => { if (body.metric === "iface.rx_packets") body.series = []; } });
  await page.locator('.react-flow__node[data-id="fw-main"]').click();
  const inspector = page.getByRole("region", { name: "Topology inspector", exact: true });
  await expect(inspector).toContainText("RX Unknown /s packets");
  await expect(inspector).toContainText("TX 2.0 /s packets");
  await expect(inspector).not.toContainText("RX 0");
});

test("IDS alert list and its detail label demo provenance", async ({ page }) => {
  await open(page, "/alerts/");
  const inspect = page.getByRole("button", { name: "Demo alertDemo", exact: true });
  await expect(inspect.getByText("Demo", { exact: true })).toBeVisible();
  await inspect.click();
  await expect(page.locator("#alert-inspection").getByText("Demo", { exact: true })).toBeVisible();
});

test("Top Protocols distinguishes no retained coverage from true zero and marks resets", async ({ page }) => {
  await page.clock.install();
  let empty = true;
  await open(page, "/monitoring/", { mutate: body => {
    if (body.metric === "proto.packets") {
      if (empty) body.series = [];
      else {
        body.series[0].points.at(-1)!.q = "reset";
        body.series[0].points.at(-1)!.v = "0";
      }
    }
  } });
  const protocols = page.getByRole("region", { name: "Top Protocols", exact: true });
  await expect(protocols).toContainText("No observed coverage in this range");
  await expect(protocols).not.toContainText("No traffic recorded yet");
  empty = false;
  await page.clock.fastForward(10_000);
  await expect(protocols).toContainText("◆ Counter reset");
  await expect(protocols).toContainText("10 · Partial coverage");
});
