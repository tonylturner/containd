import { expect, test } from "@playwright/test";

const meter = { sparkline: [], count: 0, rate_per_min: 0, errors_sparkline: [], errors_count: 0, errors_rate_per_min: 0 };

for (const service of ["dns", "ntp"] as const) {
  test(`${service} separates saved disablement from unknown runtime and keeps troubleshooting keyboard reachable`, async ({ page }) => {
    let online = false;
    const writes: string[] = [];
    await page.addInitScript(() => localStorage.setItem("containd.auth.role", "admin"));
    await page.route("**/api/v1/**", async (route) => {
      const request = route.request();
      const path = new URL(request.url()).pathname.replace("/api/v1", "");
      if (request.method() !== "GET") writes.push(request.postData() ?? "");
      let body: unknown = {};
      if (path.startsWith("/auth/")) body = { id: "admin", username: "containd", role: "admin" };
      if (path === `/services/${service}`) body = { enabled: false, servers: [], upstreamServers: [] };
      if (path === "/services/status") {
        if (!online) return route.fulfill({ status: 503, json: { error: "offline" } });
        body = { faults: [], av: { available: false, error: "scanner offline" }, [service]: { ...meter, enabled: false, running: false, pid: 42, config_path: "/data/generated.conf", last_render: "2026-11-01T12:00:00Z", last_error: "" } };
      }
      await route.fulfill({ json: body, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
    });
    await page.goto(`/system/services/${service}/`);
    const strip = page.getByRole("region", { name: "Service status", exact: true });
    await expect(strip).toContainText("Configured: disabled");
    await expect(strip).toContainText("Running: Unknown");
    await expect(strip).toContainText("Live service status unavailable");
    online = true;
    await page.getByRole("button", { name: "Refresh", exact: true }).click();
    await expect(strip).toContainText("Running: no");
    await expect(strip).toContainText("2026-11-01T12:00:00Z");
    const enable = page.getByRole("checkbox", { name: service === "dns" ? /^Enable DNS resolver/ : "Enable NTP client" });
    const activity = page.getByRole("heading", { name: "Activity", exact: true });
    expect((await enable.boundingBox())!.y).toBeLessThan((await activity.boundingBox())!.y);
    const details = page.getByRole("button", { name: /^Service details/ });
    await expect(details).toHaveAttribute("aria-expanded", "false");
    await details.focus();
    await details.press("Enter");
    await expect(details).toHaveAttribute("aria-expanded", "true");
    await expect(page.getByText("Process ID: 42", { exact: true })).toBeVisible();
    await details.press("Space");
    await expect(details).toBeFocused();
    await expect(page.getByText("Process ID: 42", { exact: true })).not.toBeVisible();
    expect(writes).toEqual([]);
    await page.setViewportSize({ width: 390, height: 844 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
  });
}

test("IDS groups auto-open saved expressions and retain the exact expression through Save", async ({ page }) => {
  const expression = "proto:modbus severity:critical";
  let ids = { enabled: true, rules: [{ id: "r1", title: "Existing detector", proto: "modbus", enabled: true }], ruleGroups: [{ id: "ot", name: "OT", filter: expression, enabled: false }] };
  const writes: unknown[] = [];
  await page.addInitScript(() => localStorage.setItem("containd.auth.role", "admin"));
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname.replace("/api/v1", "");
    let body: unknown = {};
    if (path.startsWith("/auth/")) body = { id: "admin", username: "containd", role: "admin" };
    if (path === "/ids/rules") {
      if (request.method() === "POST") { ids = request.postDataJSON(); writes.push(ids); }
      body = ids;
    }
    if (path === "/ids/sources") body = [];
    await route.fulfill({ json: body, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  await page.goto("/ids/");
  const groups = page.getByRole("button", { name: /^Groups/ });
  await expect(groups).toHaveAttribute("aria-expanded", "true");
  await expect(page.getByText(expression, { exact: true })).toBeVisible();
  await groups.click();
  await expect(groups).toHaveAttribute("aria-expanded", "false");
  await expect(page.getByText("1 group · non-default settings", { exact: true })).toBeVisible();
  await groups.press("Enter");
  await page.getByRole("button", { name: "Enable group", exact: true }).click();
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => writes.length).toBe(1);
  expect(writes[0]).toEqual({ ...ids, ruleGroups: [{ id: "ot", name: "OT", filter: expression, enabled: true }] });
  await expect(page.getByRole("row", { name: /Existing detector/ })).toBeVisible();
  await expect(page.getByText("Export uses active committed rules.", { exact: true })).toBeVisible();
});

for (const [path, endpoint] of [
  ["/dhcp/", "/services/dhcp"], ["/proxies/", "/services/proxy/reverse"],
  ["/vpn/", "/services/vpn"], ["/system/services/av/", "/services/av"],
  ["/system/services/syslog/", "/services/syslog"], ["/ids/", "/ids/rules"],
  ["/system/services/", "/services/status"],
]) {
  test(`${path} keeps the service workspace within a 390px viewport`, async ({ page }) => {
    const writes: string[] = [];
    await page.setViewportSize({ width: 390, height: 844 });
    await page.addInitScript(() => localStorage.setItem("containd.auth.role", "admin"));
    await page.route("**/api/v1/**", async (route) => {
      const request = route.request();
      const p = new URL(request.url()).pathname.replace("/api/v1", "");
      if (request.method() !== "GET") writes.push(request.postData() ?? "");
      const bodies: Record<string, unknown> = {
        "/services/status": { faults: [], av: { available: false, error: "scanner offline" } },
        "/services/dhcp": { enabled: false, listenIfaces: ["lan2"], pools: [], reservations: [] },
        "/services/vpn": { wireguard: { enabled: false, peers: [] }, openvpn: { enabled: false } },
        "/services/av": { enabled: false, mode: "clamav", clamav: { freshclamEnabled: true }, icap: { servers: [] } },
        "/services/syslog": { forwarders: [{ address: "collector.example.test", port: 514, proto: "udp" }] },
        "/services/proxy/forward": { enabled: false, listenZones: ["mgmt"] },
        "/services/proxy/reverse": { enabled: false, sites: [] },
        "/ids/rules": { enabled: true, rules: [{ id: "r1", title: "Existing detector", enabled: true }] },
        "/ids/sources": [], "/interfaces": [], "/interfaces/state": [], "/zones": [], "/assets": [],
      };
      const body = p.startsWith("/auth/") ? { id: "admin", username: "containd", role: "admin" } : bodies[p] ?? {};
      await route.fulfill({ json: body, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
    });
    const loaded = page.waitForResponse(`**/api/v1${endpoint}`);
    await page.goto(path);
    await loaded;
    if (path === "/ids/") {
      await page.getByRole("button", { name: /^Groups/ }).click();
      await expect(page.getByPlaceholder("e.g. ICS/Modbus")).toBeVisible();
    } else if (path !== "/system/services/") {
      await expect(page.getByText(/Last updated: \d/)).toBeVisible();
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
    expect(writes).toEqual([]);
  });
}
