import { expect, test, type Page } from "@playwright/test";

// Service pages chart only the per-minute series the status API reports and
// never draw a made-up trend.

const user = { id: "admin-1", username: "containd", role: "admin", mfaRequired: false };

function meter(sparkline: number[]) {
  return {
    sparkline,
    count: sparkline.reduce((a, b) => a + b, 0),
    rate_per_min: 0,
    errors_sparkline: [],
    errors_count: 0,
    errors_rate_per_min: 0,
  };
}

function servicesStatus(sparkline: number[]) {
  const m = meter(sparkline);
  return {
    syslog: { configured_forwarders: 0, protos: null, last_flush: "", last_error: "", ...m },
    dns: { enabled: true, running: true, installed: true, pid: 0, config_path: "/data/unbound.conf", last_error: "", ...m },
    ntp: { enabled: true, running: false, pid: 0, last_start: "", last_error: "", ...m },
    proxy: { envoy_running: false, nginx_running: false, envoy_last_start: "", nginx_last_start: "", ...m },
    envoy: { note: "Telemetry-only counters derived from proxy access logs.", ...m },
    nginx: { note: "Telemetry-only counters derived from proxy access logs.", ...m },
    dhcp: { enabled: true, listen_ifaces: 1, pools: 1, reservations: 0, last_error: "", note: "", ...m },
    vpn: { wireguard_enabled: false, openvpn_running: false, openvpn_mode: "client", last_error: "", ...m },
    av: { available: true, enabled: true, mode: "clamav", ready: true, block_ttl: 0, ...m },
  };
}

async function open(page: Page, path: string, status: unknown) {
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const p = new URL(route.request().url()).pathname;
    let body: unknown = {};
    if (p === "/api/v1/auth/me" || p === "/api/v1/auth/session") body = user;
    if (p === "/api/v1/services/status") body = status;
    if (p === "/api/v1/dhcp/leases") body = { leases: [] };
    if (p === "/api/v1/interfaces" || p === "/api/v1/zones" || p === "/api/v1/interfaces/state") body = [];
    await route.fulfill({ json: body });
  });
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/services/status");
  await page.goto(path);
  await loaded;
}

const pages = [
  { path: "/dhcp/", charts: ["DHCP events per minute"] },
  { path: "/system/services/syslog/", charts: ["Syslog events per minute"] },
  { path: "/system/services/ntp/", charts: ["NTP events per minute"] },
  { path: "/system/services/dns/", charts: ["DNS events per minute"] },
  { path: "/proxies/", charts: ["Envoy events per minute", "Nginx events per minute"] },
  { path: "/system/services/av/", charts: ["Engine AV scans per minute"] },
];

for (const { path, charts } of pages) {
  test(`${path} charts the reported series`, async ({ page }) => {
    await open(page, path, servicesStatus([2, 0, 5]));
    for (const title of charts) {
      const chart = page.getByTitle(title, { exact: true });
      await expect(chart).toBeVisible();
      await expect(chart.locator(":scope > div")).toHaveCount(3);
    }
  });

  test(`${path} shows no chart before any event`, async ({ page }) => {
    await open(page, path, servicesStatus([]));
    // The page stamps its refresh time once it rendered the status.
    await expect(page.getByText(/Last updated: \d/)).toBeVisible();
    await expect(page.locator("[title*='per minute']")).toHaveCount(0);
    await expect(page.locator("[title*='simulated'], [title*='trend']")).toHaveCount(0);
  });
}

test("the VPN runtime card charts the reported series", async ({ page }) => {
  await open(page, "/vpn/", servicesStatus([4, 1, 0, 2]));
  await expect(page.getByTitle("Session activity trend").locator(":scope > div")).toHaveCount(4);
});

test("the antivirus page reports an unreachable engine without runtime values", async ({ page }) => {
  await open(page, "/system/services/av/", { av: { available: false, error: "engine unavailable" } });
  await expect(page.getByText("Engine antivirus unavailable: engine unavailable")).toBeVisible();
  await expect(page.getByText("The engine did not report its runtime status.")).toBeVisible();
  await expect(page.getByText("Backend ready:")).toHaveCount(0);
});

test("topology nodes draw no made-up traffic sparklines", async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem("containd.auth.role", "admin"));
  await page.route("**/api/v1/**", async (route) => {
    const p = new URL(route.request().url()).pathname;
    let body: unknown = {};
    if (p === "/api/v1/auth/me" || p === "/api/v1/auth/session") body = user;
    if (p === "/api/v1/config") {
      body = {
        interfaces: [{ name: "lan", device: "eth9", zone: "lan" }],
        zones: [{ name: "lan" }], routing: { gateways: [], routes: [], rules: [] }, firewall: { rules: [] },
      };
    }
    if (p === "/api/v1/interfaces/state") body = [{ name: "eth9", up: true, mtu: 1500, addrs: ["192.0.2.9/24"] }];
    if (p === "/api/v1/flows" || p === "/api/v1/events") body = [];
    if (p === "/api/v1/routing/os") body = { routes: [] };
    await route.fulfill({ json: body });
  });
  await page.goto("/topology/");
  await expect(page.locator(".react-flow__node-firewall")).toBeVisible();
  await expect(page.locator(".react-flow__node-zone")).toBeVisible();
  await expect(page.locator("[class*='sparkline']")).toHaveCount(0);
});
