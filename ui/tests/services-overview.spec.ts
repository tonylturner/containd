import { expect, test, type Page } from "@playwright/test";

// The services overview charts only series the status API reports.

const user = { id: "admin-1", username: "containd", role: "admin", mfaRequired: false };

// Per-service meter fields every management service entry carries.
function meter(sparkline: number[], ratePerMin: number) {
  return {
    sparkline,
    count: sparkline.reduce((a, b) => a + b, 0),
    rate_per_min: ratePerMin,
    errors_sparkline: [],
    errors_count: 0,
    errors_rate_per_min: 0,
  };
}

const idle = meter([], 0);

function servicesStatus(av: Record<string, unknown>) {
  return {
    syslog: {
      configured_forwarders: 1,
      format: "rfc5424",
      protos: ["udp"],
      sent_total: 10,
      failed_total: 0,
      last_flush: "2026-10-26T09:15:00Z",
      last_error: "",
      ...meter([2, 5, 3], 3.3),
    },
    dns: { enabled: true, running: true, configured_upstreams: 2, last_error: "", ...idle },
    ntp: { enabled: true, running: false, servers_count: 2, last_error: "", ...idle },
    proxy: { forward_enabled: false, reverse_enabled: false, envoy_running: false, nginx_running: false, ...idle },
    dhcp: { enabled: false, listen_ifaces: 0, pools: 0, reservations: 0, last_error: "", ...idle },
    vpn: { wireguard_enabled: false, openvpn_enabled: false, openvpn_running: false, wg_peers: 0, last_error: "", ...idle },
    av,
  };
}

async function openServices(page: Page, status: unknown) {
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    let body: unknown = {};
    if (path === "/api/v1/auth/me" || path === "/api/v1/auth/session") body = user;
    if (path === "/api/v1/services/status") body = status;
    await route.fulfill({ json: body });
  });
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/services/status");
  await page.goto("/system/services/");
  await loaded;
}

test("services without a reported series show no chart", async ({ page }) => {
  await openServices(page, servicesStatus({ available: false, error: "engine unavailable" }));

  const syslog = page.getByTitle("Syslog events per minute");
  await expect(syslog).toBeVisible();
  await expect(syslog.locator(":scope > div")).toHaveCount(3);
  // Idle services and the unreachable antivirus engine have no series.
  await expect(page.locator("[title*='per minute']")).toHaveCount(1);
  await expect(page.locator("[title*='simulated']")).toHaveCount(0);

  await expect(page.getByText("Engine status unavailable: engine unavailable")).toBeVisible();
  await expect(page.getByText("Mode: icap")).toHaveCount(0);
  await expect(page.getByText("Envoy rate:")).toHaveCount(0);
});

test("antivirus charts the scans the engine reports", async ({ page }) => {
  await openServices(page, servicesStatus({
    available: true,
    enabled: true,
    mode: "clamav",
    block_ttl: 0,
    ready: true,
    ...meter([4, 1], 2.5),
  }));

  const av = page.getByTitle("AV scans per minute");
  await expect(av).toBeVisible();
  await expect(av.locator(":scope > div")).toHaveCount(2);
  await expect(page.getByText("Mode: clamav, Enabled: yes")).toBeVisible();
  await expect(page.getByText("Block TTL: 600s")).toBeVisible();
});
