import { expect, test } from "@playwright/test";
import { CONFIG_COMMITTED } from "../lib/config-events";

const meter = { sparkline: [], count: 0, rate_per_min: 0, errors_sparkline: [], errors_count: 0, errors_rate_per_min: 0 };

for (const [path, heading, entry] of [
  ["/system/services/dns/", "Live runtime status", "dns"],
  ["/system/services/ntp/", "Live runtime status", "ntp"],
  ["/dhcp/", "Live runtime status", "dhcp"],
  ["/proxies/", "Forward proxy (Envoy)", "proxy"],
  ["/proxies/", "Reverse proxy (Nginx)", "proxy"],
  ["/vpn/", "Runtime status", "vpn"],
] as const) {
  test(`${heading} on ${path} keeps unavailable telemetry unknown and refresh recovers`, async ({ page }) => {
    let available = false;
    await page.addInitScript(() => localStorage.setItem("containd.auth.role", "admin"));
    await page.route("**/api/v1/**", async (route) => {
      const p = new URL(route.request().url()).pathname.replace("/api/v1", "");
      const user = { id: "admin", username: "containd", role: "admin" };
      let body: unknown = {};
      if (["/auth/me", "/auth/session"].includes(p)) body = user;
      if (["/zones", "/interfaces", "/interfaces/state", "/assets"].includes(p)) body = [];
      if (p === "/config/diff") body = { changed: false };
      if (p === "/services/status") {
        if (!available) return route.fulfill({ status: 503, json: { error: "service status offline" } });
        body = {
          faults: [], av: { available: false, error: "scanner offline" },
          [entry]: { ...meter, installed: false, running: false, enabled: false, pools: 0, reservations: 0, listen_ifaces: 0,
            envoy_running: false, nginx_running: false, wireguard_enabled: false, openvpn_running: false,
            pid: 123, envoy_pid: 123, nginx_pid: 123, openvpn_pid: 123, config_path: "/data/generated.conf", ntpd_path: "/usr/sbin/chronyd" },
          envoy: { ...meter }, nginx: { ...meter },
        };
      }
      if (p === "/services/dns") body = { enabled: true, upstreamServers: [] };
      if (p === "/services/ntp") body = { enabled: true, servers: [] };
      if (p === "/services/dhcp") body = { enabled: true, pools: [], reservations: [] };
      if (p === "/services/vpn") body = { wireguard: { enabled: false }, openvpn: { enabled: false } };
      if (p === "/services/proxy/forward") body = { enabled: true };
      if (p === "/services/proxy/reverse") body = { enabled: true, sites: [] };
      await route.fulfill({ json: body, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
    });
    const loaded = page.waitForResponse((r) => r.url().includes("/api/v1/services/status"));
    await page.goto(path);
    await loaded;
    if (entry === "ntp") {
      const timing = page.getByText("Advanced timing", { exact: true });
      await expect(timing).toBeVisible();
      await expect(page.getByText("Requested polling interval (seconds)", { exact: true })).not.toBeVisible();
      await timing.click();
      await expect(page.getByText("Requested polling interval (seconds)", { exact: true })).toBeVisible();
      await expect(page.getByText(/Zero uses adaptive polling/)).toBeVisible();
    }
    if (entry === "vpn") {
      await page.getByText("Advanced peer settings", { exact: true }).click();
      await expect(page.getByRole("textbox", { name: /^Peers \(JSON\)/ })).toBeVisible();
      await page.getByText("Advanced profile import", { exact: true }).click();
      await expect(page.getByText("Choose file", { exact: true })).toBeVisible();
    }
    const panel = page.getByRole("heading", { name: heading, exact: true }).locator("xpath=ancestor::section[1]");
    await expect(panel).toContainText("Unknown");
    await expect(panel).not.toContainText(/(?:Running|Enabled|Live running):\s*no|(?:Rate|Errors|Pools|Reservations|Listen ifaces):\s*0/);
    available = true;
    await page.getByRole("button", { name: "Refresh", exact: true }).first().click();
    await expect(panel).toContainText(/(?:Rate|Errors):\s*0.0/);
    await expect(panel).not.toContainText("status unavailable");
    if (entry !== "dhcp") {
      await expect(panel.getByText("Process ID: 123", { exact: true })).not.toBeVisible();
      await panel.getByText("Service details", { exact: true }).click();
      await expect(panel.getByText("Process ID: 123", { exact: true })).toBeVisible();
    }
    available = false;
    await page.getByRole("button", { name: "Refresh", exact: true }).first().click();
    await expect(panel).toContainText("Unknown");
    await expect(panel).not.toContainText(/(?:Rate|Errors):\s*0.0/);
  });
}

for (const ntpd_path of ["", undefined, "/usr/sbin/chronyd"]) {
  test(`NTP binary reports ${ntpd_path === "" ? "not found" : ntpd_path ?? "unknown"} without inventing discovery`, async ({ page }) => {
    await page.route("**/api/v1/**", async (route) => {
      const path = new URL(route.request().url()).pathname;
      const body = path.endsWith("/services/status") ? { faults: [], av: { available: false, error: "scanner offline" }, ntp: { ...meter, running: false, ntpd_path } }
        : path.endsWith("/services/ntp") ? { enabled: true, servers: [] }
          : path.endsWith("/auth/me") || path.endsWith("/auth/session") ? { id: "admin", username: "containd", role: "admin" } : {};
      await route.fulfill({ json: body, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
    });
    const loaded = page.waitForResponse("**/api/v1/services/status");
    await page.goto("/system/services/ntp/");
    await loaded;
    await page.getByText("Service details", { exact: true }).click();
    await expect(page.getByText(`Binary: ${ntpd_path === "" ? "not found" : ntpd_path ?? "Unknown"}`, { exact: true })).toBeVisible();
  });
}

test("saved WireGuard peers are visible by default without dirtying configuration", async ({ page }) => {
  let peers = [{ name: "operator", publicKey: "test-key", allowedIPs: ["10.8.0.2/32"] }];
  let revision = 1;
  const writes: string[] = [];
  await page.addInitScript(() => localStorage.setItem("containd.auth.role", "admin"));
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (request.method() !== "GET") writes.push(request.postData() ?? "");
    const body = path.endsWith("/services/vpn") ? { wireguard: { enabled: false, peers }, openvpn: { enabled: false } }
      : ["/interfaces", "/interfaces/state", "/zones"].some((p) => path.endsWith(p)) ? []
        : path.endsWith("/auth/me") || path.endsWith("/auth/session") ? { id: "admin", username: "containd", role: "admin" } : {};
    await route.fulfill({ json: body, headers: { "X-Containd-Revision": `0123456789abcdef.${revision}` } });
  });
  const loaded = page.waitForResponse("**/api/v1/services/vpn");
  await page.goto("/vpn/");
  await loaded;
  await expect(page.getByRole("textbox", { name: /^Peers \(JSON\)/ })).toBeVisible();
  await expect(page.getByRole("textbox", { name: /^Peers \(JSON\)/ })).toHaveValue(JSON.stringify(peers, null, 2));
  peers = [...peers, { name: "engineer", publicKey: "new-key", allowedIPs: ["10.8.0.3/32"] }];
  revision++;
  await Promise.all([
    page.waitForResponse("**/api/v1/services/vpn"),
    page.evaluate((event) => window.dispatchEvent(new CustomEvent(event)), CONFIG_COMMITTED),
  ]);
  await expect(page.getByRole("textbox", { name: /^Peers \(JSON\)/ })).toHaveValue(JSON.stringify(peers, null, 2));
  await expect(page.getByRole("status", { name: "Unsaved edits" })).toHaveCount(0);
  expect(writes).toEqual([]);
});
