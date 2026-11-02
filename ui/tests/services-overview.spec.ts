import { seriesResponse } from "./fixtures/telemetry";
import { expect, test, type Page } from "@playwright/test";

// The services overview charts only retained counter observations.

const user = { id: "admin-1", username: "containd", role: "admin", mfaRequired: false };

// Per-service meter fields every management service entry carries.
function meter(sparkline: number[]) {
  return {
    count: sparkline.reduce((a, b) => a + b, 0),
    errors_count: 0,
  };
}

const idle = meter([]);

function servicesStatus(av: Record<string, unknown>) {
  return {
    faults: [],
    syslog: {
      configured_forwarders: 1,
      format: "rfc5424",
      protos: ["udp"],
      sent_total: 10,
      failed_total: 0,
      last_flush: "2026-10-26T09:15:00Z",
      last_error: "",
      ...meter([2, 5, 3]),
    },
    dns: { enabled: true, running: true, configured_upstreams: 2, last_error: "", ...idle },
    ntp: { enabled: true, running: false, servers_count: 2, last_error: "", ...idle },
    proxy: { forward_enabled: false, reverse_enabled: false, envoy_running: false, nginx_running: false, ...idle },
    dhcp: { enabled: false, listen_ifaces: 0, pools: 0, reservations: 0, last_error: "", ...idle },
    vpn: { wireguard_enabled: false, openvpn_enabled: false, openvpn_running: false, wg_peers: 0, last_error: "", ...idle },
    av,
  };
}

async function openServices(page: Page, status: unknown, history: Record<string, number[]> = { syslog: [2, 5, 3] }, errors = false) {
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    if (path === "/api/v1/telemetry/series") {
      const key = url.searchParams.get("service") ?? "av";
      const errorSeries = url.searchParams.get("metric") === "service.errors";
      const body = seriesResponse(url, errorSeries ? errors ? [1] : [] : history[key] ?? []);
      if (errorSeries && errors) Object.assign(body.series[0].points.at(-1)!, { q: "partial", v: "1", d: 30 });
      return route.fulfill({ json: body });
    }
    let body: unknown = {};
    if (path === "/api/v1/auth/me" || path === "/api/v1/auth/session") body = user;
    if (path === "/api/v1/services/status") body = status;
    await route.fulfill({ json: body, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/services/status");
  await page.goto("/system/services/");
  await loaded;
}

test("services without a reported series show no chart", async ({ page }) => {
  await openServices(page, servicesStatus({ available: false, error: "engine unavailable" }));

  const syslog = page.getByTitle("Syslog events per minute");
  await expect(syslog).toBeVisible();
  await expect(syslog.locator("[data-bar]")).toHaveCount(3);
  // Idle services and the unreachable antivirus engine have no series.
  await expect(page.locator("[title*='per minute']")).toHaveCount(1);
  await expect(page.locator("[title*='simulated']")).toHaveCount(0);

  await expect(page.getByText("Scanner status unavailable: engine unavailable")).toBeVisible();
  await expect(page.getByText("Mode: icap")).toHaveCount(0);
  await expect(page.getByText(/Forward proxy activity:/)).toContainText("Forward proxy activity: Unknown /min");
});

test("antivirus charts the scans the engine reports", async ({ page }) => {
  await openServices(page, servicesStatus({
    available: true,
    enabled: true,
    mode: "clamav",
    ready: true,
    ...meter([4, 1]),
  }), { syslog: [2, 5, 3], av: [4, 1] });

  const av = page.getByTitle("AV scans per minute");
  await expect(av).toBeVisible();
  await expect(av.locator("[data-bar]")).toHaveCount(2);
  await expect(page.getByText("Mode: clamav, Enabled: yes")).toBeVisible();
});

test("missing service entries stay unknown on the overview", async ({ page }) => {
  await openServices(page, { faults: [], av: { available: false, error: "offline" } });
  for (const name of ["DNS", "NTP", "DHCP", "VPN", "Proxies", "Syslog"]) {
    const card = page.locator("p").filter({ hasText: new RegExp(`^${name}$`) }).locator("..");
    await expect(card).toContainText("Unknown");
    await expect(card).not.toContainText(/Enabled:\s*no|running:\s*no|Forwarders:\s*0/);
  }
});

for (const width of [1280, 390]) {
  test(`service software identities stay in keyboard-accessible troubleshooting at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 844 });
    await openServices(page, servicesStatus({ available: false, error: "scanner offline" }));
    for (const [name, software] of [["Proxies", "Envoy + Nginx"], ["DNS", "Unbound"], ["NTP", "chrony"]]) {
      const card = page.locator("p").filter({ hasText: new RegExp(`^${name}$`) }).locator("..");
      const identity = card.getByText(`Software: ${software}`, { exact: true });
      await expect(identity).not.toBeVisible();
      const details = card.getByRole("button", { name: "Service details", exact: true });
      await details.focus();
      await details.press("Enter");
      await expect(identity).toBeVisible();
      await details.press("Space");
      await expect(identity).not.toBeVisible();
      await expect(details).toBeFocused();
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
  });
}

for (const values of [[], [0], [5], [0, 0, 0]]) {
  test(`overview distinguishes observed quiet history from absent history for ${JSON.stringify(values)}`, async ({ page }) => {
    const status = servicesStatus({ available: false, error: "scanner offline" });
    status.dns = { ...status.dns, ...meter(values), errors_count: 2 };
    status.syslog = { ...status.syslog, ...meter(values), errors_count: 2 };
    await openServices(page, status, { dns: values, syslog: values }, true);
    for (const name of ["DNS", "Syslog"]) {
      const card = page.locator("p").filter({ hasText: new RegExp(`^${name}$`) }).locator("..");
      if (values.length) await expect(card).toContainText(`Rate: ${(values.at(-1)! * 6).toFixed(1)} /min`);
      else await expect(card).toContainText("No traffic recorded yet");
      await expect(card).toContainText("Errors: 2.0 /min");
      await expect(card.locator("[title*='events per minute'] [data-bar]")).toHaveCount(values.length);
      if (values.length < 2) await expect(card).not.toContainText("Trend:");
      else await expect(card).toContainText("Trend: • 0");
    }
  });
}

for (const width of [1280, 390]) {
  test(`overview draws real bars for a reported declining series at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 844 });
    const status = servicesStatus({ available: false, error: "scanner offline" });
    status.dns = { ...status.dns, ...meter([1, 0]) };
    status.syslog = { ...status.syslog, ...meter([1, 0]) };
    await openServices(page, status, { dns: [1, 0], syslog: [1, 0] });
    for (const name of ["DNS", "Syslog"]) {
      const chart = page.getByTitle(`${name} events per minute`, { exact: true });
      await expect(chart).toBeVisible();
      await expect(chart.locator("[data-bar]")).toHaveCount(2);
      expect((await chart.locator("[data-bar]").first().boundingBox())!.height).toBeGreaterThan(20);
      await expect(chart.locator("..")).toContainText("▼ -6");
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
  });
}
