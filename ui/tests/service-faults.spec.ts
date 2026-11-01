import { expect, test, type Page } from "@playwright/test";
import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import type { ServiceFault } from "../lib/api-service-status";

const meter = { sparkline: [], count: 0, rate_per_min: 0, errors_sparkline: [], errors_count: 0, errors_rate_per_min: 0 };
const avConfig = {
  enabled: true, mode: "clamav", failPolicy: "closed", httpDownload: true,
  scan: { include: [{ sourceZones: ["lan"], destPorts: ["80"] }], downloadMode: "hold" },
};

function statusWith(faults: ServiceFault[] = [], policy = "closed", available = true) {
  const status: Record<string, unknown> = {
    faults,
    dns: { ...meter, enabled: true, running: true },
    ntp: { ...meter, enabled: true, running: false },
    syslog: { ...meter, configured_forwarders: 0 },
    vpn: { ...meter, wireguard_enabled: false, openvpn_running: false },
    wireguard: { ...meter }, openvpn: { ...meter },
    av: available ? {
      ...meter, available: true, enabled: !faults.some((f) => f.service === "av"),
      mode: "clamav", ready: false, failPolicy: policy,
      gate: {
        state: policy === "closed" ? "refuse" : "pass", enabled: true,
        fail_policy: policy, admit: policy === "closed" ? "refuse" : "pass",
        listeners: [], scanner: { ready: false }, connections: 0,
      },
    } : { available: false, error: "engine unreachable" },
  };
  for (const fault of faults) {
    status[fault.service] = { ...(status[fault.service] as object ?? meter), state: "faulted", fault };
  }
  return status;
}

async function mockAPI(page: Page, initial: unknown, policy = "closed") {
  let counter = 1;
  const revision = () => `0123456789abcdef.${counter}`;
  const server = { status: initial, writes: [] as { path: string; body: unknown }[] };
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname.replace("/api/v1", "");
    if (request.method() !== "GET") {
      const body: unknown = request.postDataJSON();
      expect(request.headers()["x-containd-if-revision"]).toBe(revision());
      server.writes.push({ path, body });
      counter++;
      await route.fulfill({ json: body, headers: { "X-Containd-Config": "staged", "X-Containd-Revision": revision() } });
      return;
    }
    const bodies: Record<string, unknown> = {
      "/auth/me": { id: "admin", username: "containd", role: "admin" },
      "/auth/session": { id: "admin", username: "containd", role: "admin" },
      "/health": { status: "ok", evidence: { state: "ok" } },
      "/services/status": server.status,
      "/services/dns": { enabled: true, listenPort: 53, upstreamServers: ["192.0.2.53"] },
      "/services/ntp": { enabled: true, servers: ["ntp.example.test"] },
      "/services/syslog": { forwarders: [] },
      "/services/av": { ...avConfig, failPolicy: policy },
      "/services/av/defs": { files: [], path: "/data/clamav", definitions: [] },
      "/services/vpn": { wireguard: { enabled: true, interface: "plant0", peers: [] }, openvpn: { enabled: true } },
      "/zones": [{ name: "lan" }], "/assets": [], "/interfaces": [], "/interfaces/state": [],
      "/config/diff": { changed: false, changedSections: [] },
    };
    await route.fulfill({ json: bodies[path] ?? {}, headers: { "X-Containd-Revision": revision() } });
  });
  return server;
}

async function open(page: Page, path = "/system/services/") {
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/services/status");
  await page.goto(path);
  await loaded;
}

const banner = (page: Page) => page.getByRole("status", { name: "Service faults" });
const configFault: ServiceFault = { service: "dns", kind: "config", message: "runtime apply failed" };
const runtimeFault: ServiceFault = { service: "ntp", kind: "runtime", message: "config rejected" };

async function screenshot(page: Page, name: string) {
  const dir = process.env.SERVICE_FAULT_SHOTS;
  if (!dir) return;
  await mkdir(dir, { recursive: true });
  await page.screenshot({ path: join(dir, `${name}.png`), fullPage: true });
}

test("config faults explain quarantine and repair, regardless of message wording", async ({ page }) => {
  await mockAPI(page, statusWith([configFault]));
  await open(page);
  await expect(banner(page)).toContainText("DNS — Settings need attention");
  await expect(banner(page).getByText(configFault.message, { exact: true })).toBeVisible();
  await expect(banner(page)).toContainText("Edit or clear them");
  await expect(banner(page)).toContainText("Unrelated edits can still be saved");
  await expect(banner(page)).toContainText("Remote clients cannot connect unless access is explicitly allowed");
  await expect(banner(page).getByRole("link", { name: "Configure DNS" })).toHaveAttribute("href", "/system/services/dns/");
  await screenshot(page, "config-fault");
});

test("runtime faults explain retry, not stored quarantine", async ({ page }) => {
  await mockAPI(page, statusWith([runtimeFault]));
  await open(page);
  await expect(banner(page)).toContainText("NTP — Service could not run");
  await expect(banner(page).getByText(runtimeFault.message, { exact: true })).toBeVisible();
  await expect(banner(page)).toContainText("Applying configuration again retries this service");
  await expect(banner(page)).not.toContainText("These saved settings were rejected");
  await screenshot(page, "runtime-fault");
});

test("multiple faults are visible together and clear after a successful later apply", async ({ page }) => {
  const server = await mockAPI(page, statusWith([configFault, runtimeFault]));
  await open(page);
  await expect(banner(page).getByRole("listitem")).toHaveCount(2);
  await screenshot(page, "multiple-faults");
  server.status = statusWith();
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(banner(page)).toHaveCount(0);
});

test("overview names every independent service and renders diagnostics as text", async ({ page }) => {
  const faults = (["av", "dhcp", "dns", "ntp", "openvpn", "proxy", "syslog", "wireguard"] as const)
    .map((service) => ({ service, kind: "config" as const, message: "<b>invalid section</b>" }));
  await mockAPI(page, statusWith(faults));
  await open(page);
  await expect(banner(page).getByRole("listitem")).toHaveCount(8);
  for (const label of ["Antivirus / ICAP", "DHCP", "DNS", "NTP", "OpenVPN", "Proxies", "Syslog", "WireGuard"]) {
    await expect(banner(page).getByRole("heading", { name: `${label} — Settings need attention`, exact: true })).toBeVisible();
  }
  await expect(banner(page).locator("b")).toHaveCount(0);
  await expect(banner(page).getByText("<b>invalid section</b>", { exact: true })).toHaveCount(8);
});

for (const [service, path, label] of [
  ["dns", "/system/services/dns/", "DNS"],
  ["ntp", "/system/services/ntp/", "NTP"],
  ["syslog", "/system/services/syslog/", "Syslog"],
] as const) {
  test(`${label} settings show the fault without disabling repair`, async ({ page }) => {
    await mockAPI(page, statusWith([{ ...configFault, service }]));
    await open(page, path);
    await expect(banner(page)).toContainText(`${label} — Settings need attention`);
    await expect(page.getByRole("button", { name: "Save", exact: true })).toBeEnabled();
    await expect(banner(page).getByRole("link")).toHaveCount(0);
  });
}

test("unrelated DNS edits still save while Syslog is quarantined", async ({ page }) => {
  const server = await mockAPI(page, statusWith([{ ...configFault, service: "syslog" }]));
  await open(page, "/system/services/dns/");
  await expect(banner(page)).toHaveCount(0);
  await page.getByLabel("Enable DNS resolver").uncheck();
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByRole("status", { name: "Save state" })).toContainText("staged");
  expect(server.writes).toEqual([{ path: "/services/dns", body: { enabled: false, listenPort: 53, upstreamServers: ["192.0.2.53"] } }]);
});

for (const policy of ["closed", "open"]) {
  test(`AV quarantine preserves ${policy} policy and selection alongside runtime status`, async ({ page }) => {
    const fault: ServiceFault = { service: "av", kind: "config", message: "scanner configuration rejected" };
    await mockAPI(page, statusWith([fault], policy), policy);
    await open(page, "/system/services/av/");
    await expect(banner(page)).toContainText("Antivirus / ICAP — Settings need attention");
    await expect(banner(page)).toContainText("Scanner unavailable; scan selection and fail policy still apply");
    await expect(banner(page)).toContainText(policy === "closed" ? "Closed policy still blocks" : "Open policy permits selected traffic unscanned");
    await expect(page.getByText(/Settings show AV/)).toHaveCount(0);
    await expect(page.getByLabel("Enable AV/ICAP scanning")).toBeChecked();
    await expect(page.getByTestId("scan-include").getByLabel("Destination ports")).toHaveValue("80");
    await expect(page.getByTestId("gate-status")).toContainText(`Fail policy: ${policy}`);
    await screenshot(page, `av-quarantine-${policy}`);
    // Staged form edits must not be described as the applied policy.
    await page.locator("select").filter({ has: page.locator('option[value="closed"]') }).selectOption(policy === "closed" ? "open" : "closed");
    await expect(banner(page)).toContainText(policy === "closed" ? "Closed policy still blocks" : "Open policy permits");
    await open(page);
    await expect(banner(page)).toContainText("Scanner unavailable");
    await expect(page.getByText("Mode: clamav, Enabled: no")).toBeVisible();
  });
}

test("AV faults remain visible when the engine is unreachable without guessing its live policy", async ({ page }) => {
  await mockAPI(page, statusWith([{ service: "av", kind: "config", message: "invalid scanner" }], "closed", false));
  await open(page, "/system/services/av/");
  await expect(banner(page)).toContainText("invalid scanner");
  await expect(banner(page)).toContainText("Closed policy still blocks");
  await expect(banner(page)).toContainText("open policy permits it");
  await expect(page.getByText("Antivirus status unavailable: engine unreachable")).toBeVisible();
});

test("VPN keeps WireGuard and OpenVPN fault identities independent", async ({ page }) => {
  await mockAPI(page, statusWith([
    { service: "wireguard", kind: "config", message: "invalid tunnel address" },
    { service: "openvpn", kind: "runtime", message: "runtime apply failed" },
  ]));
  await open(page, "/vpn/");
  await expect(banner(page)).toContainText("WireGuard — Settings need attention");
  await expect(banner(page)).toContainText("WireGuard tunnel settings were rejected: rules targeting this tunnel do not match traffic");
  await expect(banner(page)).toContainText("OpenVPN — Service could not run");
  await expect(page.getByRole("region", { name: "VPN runtime status" })).toContainText("WireGuard: faulted");
  await expect(page.getByRole("region", { name: "VPN runtime status" })).toContainText("OpenVPN: faulted");
  await screenshot(page, "vpn-faults");
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(banner(page)).toBeVisible();
  expect(await banner(page).evaluate((el) => el.scrollWidth <= el.clientWidth)).toBe(true);
  await screenshot(page, "vpn-faults-mobile");
});

test("an empty faults list has no banner", async ({ page }) => {
  await mockAPI(page, statusWith());
  await open(page);
  await expect(banner(page)).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Services", exact: true })).toBeVisible();
  await screenshot(page, "no-faults");
});

for (const [name, body] of [
  ["list body", []], ["null body", null], ["missing faults", { av: { available: false } }],
  ["non-list faults", { ...statusWith(), faults: {} }],
  ["unknown kind", { ...statusWith(), faults: [{ ...configFault, kind: "unknown" }] }],
  ["non-text message", { ...statusWith(), faults: [{ ...configFault, message: {} }] }],
  ["broken entry", { ...statusWith(), dns: [] }],
  ["broken meter", { ...statusWith(), dns: { sparkline: "invalid" } }],
  ["missing AV meter", { ...statusWith(), av: { available: true } }],
  ["broken AV gate", { ...statusWith(), av: { available: true, ...meter, gate: {} } }],
  ["fault without state", { ...statusWith(), faults: [configFault] }],
  ["state without fault", { ...statusWith(), dns: { ...meter, state: "faulted" } }],
] as const) {
  test(`malformed status (${name}) is unavailable, never healthy or a crash`, async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    await mockAPI(page, body);
    await open(page);
    await expect(banner(page)).toContainText("Service status unavailable");
    expect(errors).toEqual([]);
    if (name === "non-list faults") await screenshot(page, "unavailable");
  });
}

for (const path of ["/system/services/dns/", "/system/services/ntp/", "/system/services/syslog/", "/system/services/av/", "/vpn/"]) {
  test(`${path} reports malformed status as unavailable and recovers on refresh`, async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    const server = await mockAPI(page, { ...statusWith(), faults: "invalid" });
    await open(page, path);
    await expect(banner(page)).toContainText("Service status unavailable");
    server.status = statusWith();
    await page.getByRole("button", { name: "Refresh", exact: true }).click();
    await expect(banner(page)).toHaveCount(0);
    expect(errors).toEqual([]);
  });
}
