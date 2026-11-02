import { expect, test, type Page } from "@playwright/test";

const meter = { sparkline: [], count: 0, rate_per_min: 0, errors_sparkline: [], errors_count: 0, errors_rate_per_min: 0 };
const audit = { enabled: true, sent_total: 4, failed_total: 0, last_error: "", last_flush: "", backlog: 0, forwarders: [] };
const syslog = { ...meter, configured_forwarders: 1, sent_total: 4, failed_total: 0, last_error: "", last_batch: 17, events: [], audit };
const gate = { state: "open", enabled: true, fail_policy: "closed", admit: "open", listeners: [], scanner: { ready: true }, connections: 0 };
const status = {
  faults: [],
  dns: { ...meter, enabled: true, running: true, pid: 42, config_path: "/data/unbound.conf" },
  ntp: { ...meter, enabled: true, running: true, pid: 42, ntpd_path: "/usr/sbin/chronyd" },
  proxy: { ...meter, envoy_running: true, nginx_running: true, envoy_pid: 42, nginx_pid: 43 },
  vpn: { ...meter, openvpn_running: true, openvpn_pid: 42, openvpn_config_path: "/data/openvpn.conf" },
  dhcp: { ...meter, enabled: true },
  av: { ...meter, available: true, enabled: true, mode: "clamav", ready: true, clamav_pid: 42, clamav_running: true, clamav_socket: "/run/clamd.sock", gate },
  syslog,
};
const configs: Record<string, unknown> = {
  "/services/dns": { enabled: true, upstreamServers: [] },
  "/services/ntp": { enabled: true, servers: [] },
  "/services/av": { enabled: true, mode: "clamav", clamav: { freshclamEnabled: true } },
  "/services/syslog": { forwarders: [{ address: "collector.example.test", port: 514 }] },
  "/services/proxy/forward": { enabled: true },
  "/services/proxy/reverse": { enabled: true, sites: [] },
  "/services/vpn": { wireguard: { enabled: true, peers: [] }, openvpn: { enabled: true } },
  "/services/dhcp": { enabled: true, pools: [], reservations: [] },
  "/ids/rules": { enabled: true, rules: [{ id: "r1", title: "Existing detector", enabled: true }], ruleGroups: [{ id: "ot", name: "OT", enabled: true, filter: "proto:modbus" }] },
};

async function mock(page: Page, live: unknown = status, fails: (path: string) => boolean = () => false) {
  const writes: string[] = [];
  await page.addInitScript(() => localStorage.setItem("containd.auth.role", "admin"));
  await page.route("**/api/v1/**", async route => {
    const request = route.request();
    const path = new URL(request.url()).pathname.replace("/api/v1", "");
    if (request.method() !== "GET") writes.push(request.postData() ?? "");
    if (fails(path)) return route.fulfill({ status: 503, json: { error: "Configuration unavailable" } });
    const body = path.startsWith("/auth/") ? { id: "admin", username: "containd", role: "admin" }
      : path === "/services/status" ? live
        : configs[path] ?? (["/zones", "/assets", "/interfaces", "/interfaces/state", "/ids/sources", "/services/dhcp/leases"].includes(path) ? [] : {});
    await route.fulfill({ json: body, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  return writes;
}

for (const [path, endpoint, label, detail] of [
  ["/system/services/dns/", "/services/dns", "Service details", "Process ID: 42"],
  ["/system/services/ntp/", "/services/ntp", "Service details", "Process ID: 42"],
  ["/system/services/av/", "/services/av", "Service details", "ClamAV socket: /run/clamd.sock"],
  ["/system/services/syslog/", "/services/syslog", "Delivery details", "Last batch: 17"],
  ["/proxies/", "/services/proxy/forward", "Service details", "Process ID: 42"],
  ["/vpn/", "/services/vpn", "Service details", "OpenVPN config: /data/openvpn.conf"],
]) {
  test(`${path} troubleshooting works when configuration fails but status succeeds`, async ({ page }) => {
    const writes = await mock(page, status, p => p === endpoint);
    await page.goto(path);
    const details = page.getByRole("button", { name: new RegExp(`^${label}`) });
    await expect(details.first()).toBeEnabled();
    for (const button of await details.all()) {
      await button.focus();
      await button.press("Enter");
      await expect(button).toHaveAttribute("aria-expanded", "true");
      expect(await button.evaluate(el => el.closest("fieldset[disabled]"))).toBeNull();
      await expect(page.locator(`[id="${await button.getAttribute("aria-controls")}"]`)).toBeVisible();
    }
    await expect(page.getByText(detail, { exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: /^Save/ }).first()).toBeDisabled();
    for (const input of await page.locator('main input:not([type="hidden"]), main textarea, main select').all()) {
      // Auto-refresh and immediate definition actions are not staged settings.
      if (await input.evaluate(el => el.closest('[aria-label="Immediate definition actions"]') !== null)) continue;
      if (await input.getAttribute("type") === "checkbox" && await input.isEnabled()) {
        await expect(input.locator("..")).toContainText("Auto");
      } else {
        await expect(input).toBeDisabled();
      }
    }
    expect(writes).toEqual([]);
  });
}

test("DHCP lease refresh stays usable when configuration cannot load", async ({ page }) => {
  const writes = await mock(page, status, p => p === "/services/dhcp");
  await page.goto("/dhcp/");
  await expect(page.getByRole("button", { name: "Save", exact: true })).toBeDisabled();
  await expect(page.getByRole("checkbox", { name: /^Enable DHCP/ })).toBeDisabled();
  const refresh = page.locator("section").filter({ has: page.getByRole("heading", { name: "Active Leases", exact: true }) }).getByRole("button", { name: "Refresh", exact: true });
  await expect(refresh).toBeEnabled();
  await refresh.click();
  expect(writes).toEqual([]);
});

test("DHCP reports its available diagnostics inline without an empty troubleshooting expander", async ({ page }) => {
  await mock(page, { ...status, dhcp: { ...status.dhcp, pools: 2, reservations: 3, listen_ifaces: 1,
    note: "DHCP runtime is handled by the engine; this status reflects config render state.",
    last_error: "Configuration render failed",
  } });
  await page.goto("/dhcp/");
  const activity = page.getByRole("heading", { name: "Live runtime status", exact: true }).locator("xpath=ancestor::section[1]");
  await expect(activity).toContainText("Pools: 2");
  await expect(activity).toContainText("Reservations: 3");
  await expect(activity).toContainText("Listen ifaces: 1");
  await expect(activity.getByText("DHCP runtime is handled by the engine; this status reflects config render state.")).toBeVisible();
  await expect(activity.getByText("Configuration render failed")).toBeVisible();
  await expect(page.getByRole("button", { name: "Service details", exact: true })).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Troubleshooting", exact: true })).toHaveCount(0);
});

test("IDS retained rules and inspection stay readable after a failed refresh without enabling mutations", async ({ page }) => {
  let failed = false;
  const writes = await mock(page, status, p => failed && p === "/ids/rules");
  await page.goto("/ids/");
  await expect(page.getByRole("row", { name: /Existing detector/ })).toBeVisible();
  failed = true;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.getByRole("button", { name: "Save", exact: true })).toBeDisabled();
  const groups = page.getByRole("button", { name: /^Groups/ });
  await groups.click();
  await groups.click();
  await expect(page.locator("code.truncate").filter({ hasText: "proto:modbus" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Disable group", exact: true })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Edit", exact: true })).toBeDisabled();
  await page.getByRole("button", { name: "Sources", exact: false }).click();
  await expect(page.getByText("No rule sources", { exact: true })).toBeVisible();
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole("button", { name: "Import", exact: true }).click();
  await expect(page.locator('input[type="file"]')).toBeDisabled();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
  expect(writes).toEqual([]);
});

test("healthy syslog keeps the delivery caveat muted rather than amber attention", async ({ page }) => {
  await mock(page);
  await page.goto("/system/services/syslog/");
  const strip = page.getByRole("region", { name: "Service status", exact: true });
  await expect(strip).toContainText("Configured: 1 forwarders");
  await expect(strip).toContainText("Attention: No fault reported; not proof of protection");
  await expect(strip.getByText("Delivery is not an acknowledgement by the collector", { exact: true })).toHaveClass(/text-\(--text-muted\)/);
  await expect(strip.locator(".text-amber")).toHaveCount(0);
});

for (const [state, effect] of [
  ["open", "Scanning the selected HTTP traffic."],
  ["pending", "Waiting for the scanner to become ready."],
  ["refuse", "selected connections are refused; ICS endpoints pass."],
  ["pass", "selected connections pass unscanned."],
  ["off", "Off: firewall enforcement is off."],
]) {
  test(`AV ${state} scan path and traffic effect lead the settings`, async ({ page }) => {
    await mock(page, { ...status, av: { ...status.av, gate: { ...gate, state, admit: state === "pass" ? "pass" : "refuse" } } });
    await page.goto("/system/services/av/");
    const strip = page.getByRole("region", { name: "Service status", exact: true });
    await expect(strip).toContainText(`Scan path: ${state}`);
    await expect(strip).toContainText(effect);
    expect((await strip.boundingBox())!.y).toBeLessThan((await page.getByRole("heading", { name: "Settings", exact: true }).boundingBox())!.y);
  });
}

test("unreported AV scan path is Unknown rather than off or protected", async ({ page }) => {
  await mock(page, { ...status, av: { ...status.av, gate: undefined } });
  await page.goto("/system/services/av/");
  await expect(page.getByRole("region", { name: "Service status", exact: true })).toContainText("Scan path: Unknown");
});

test("an open AV gate without a selection does not claim it is scanning traffic", async ({ page }) => {
  await mock(page, { ...status, av: { ...status.av, gate: { ...gate, enabled: false } } });
  await page.goto("/system/services/av/");
  await expect(page.getByRole("region", { name: "Service status", exact: true })).toContainText("Ready; no traffic is selected.");
});

for (const [policy, effect] of [["open", "pass unscanned"], ["closed", "are refused"]]) {
  test(`pending AV explains the ${policy} unscanned-traffic effect in the summary`, async ({ page }) => {
    await mock(page, { ...status, av: { ...status.av, gate: { ...gate, state: "pending", fail_policy: policy } } });
    await page.goto("/system/services/av/");
    await expect(page.getByRole("region", { name: "Service status", exact: true })).toContainText(`Selected HTTP objects ${effect} while the scanner is unavailable.`);
  });
}

test("syslog loss, continuity gaps and audit failures lead the forwarder settings", async ({ page }) => {
  await mock(page, { ...status, syslog: { ...syslog,
    events: [{ destination: "tcp://collector:514", source: "engine", epoch: "run", offset: "1", backlog: 3, sent: 4, failed: 2, lost: 7, continuity_unknown: 2, last_error: "offline", last_success: "" }],
    audit: { ...audit, failed_total: 5, backlog: 8, last_error: "collector offline" },
  } });
  await page.goto("/system/services/syslog/");
  const strip = page.getByRole("region", { name: "Service status", exact: true });
  await expect(strip).toContainText("Telemetry loss reported");
  await expect(strip).toContainText("additional loss unknown");
  await expect(strip).toContainText("7 known lost deliveries; 2 continuity gaps; 3 queued");
  await expect(strip).toContainText("5 failed attempts; 8 queued. Audit loss is not reported.");
  expect((await strip.boundingBox())!.y).toBeLessThan((await page.getByRole("heading", { name: "Forwarders", exact: true }).boundingBox())!.y);
});

test("missing syslog progress remains unknown in the summary", async ({ page }) => {
  await mock(page, { ...status, syslog: { ...syslog, events: undefined, audit: undefined } });
  await page.goto("/system/services/syslog/");
  const strip = page.getByRole("region", { name: "Service status", exact: true });
  await expect(strip).toContainText("Telemetry loss and continuity: Unknown.");
  await expect(strip).toContainText("Audit forwarding: Unknown; audit loss is not reported.");
});

test("audit forwarding failure alone raises top-strip attention", async ({ page }) => {
  await mock(page, { ...status, syslog: { ...syslog, audit: { ...audit, backlog: 8, failed_total: 2 } } });
  await page.goto("/system/services/syslog/");
  const strip = page.getByRole("region", { name: "Service status", exact: true });
  await expect(strip.getByText("Attention: Audit forwarding needs attention", { exact: true })).toHaveClass(/text-amber/);
  await expect(strip).toContainText("2 failed attempts; 8 queued. Audit loss is not reported.");
});
