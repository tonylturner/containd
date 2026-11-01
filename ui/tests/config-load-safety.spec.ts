import { expect, test, type Page, type Response } from "@playwright/test";
import { CONFIG_COMMITTED } from "../lib/config-events";

const prefix = "/api/v1";
const revision = (counter: number) => `0123456789abcdef.${counter}`;
const read = (path: string) => (r: Response) =>
  new URL(r.url()).pathname === prefix + path && r.request().method() === "GET";

const data: Record<string, unknown> = {
  "/zones": [{ name: "lan" }, { name: "wan" }],
  "/interfaces": [{ name: "wan", zone: "wan", device: "eth0" }],
  "/interfaces/state": [{ name: "eth0", addrs: ["192.0.2.2/24"] }],
  "/firewall/rules": [],
  "/firewall/nat": { enabled: false, portForwards: [{ id: "existing", externalPort: 8443 }] },
  "/routing": { gateways: [], routes: [{ dst: "198.51.100.0/24", iface: "eth0" }], rules: [] },
  "/dataplane": { captureInterfaces: [], dpiMock: false, dpiEnabled: true },
  "/pcap/config": { enabled: false, interfaces: ["wan"], zones: [], snaplen: 4096, maxSizeMB: 32, maxFiles: 5, mode: "once", promisc: false, bufferMB: 8, rotateSeconds: 120, filePrefix: "existing", filter: { src: "192.0.2.10", dst: "198.51.100.10", proto: "tcp", port: "443" }, forwardTargets: [{ interface: "eth0", enabled: true, host: "192.0.2.20", port: 9001, proto: "tcp" }] },
  "/pcap/status": { running: false },
  "/pcap/list": [],
  "/ids/rules": { enabled: false, rules: [{ id: "existing", title: "Existing", enabled: true }], ruleGroups: [{ id: "group", name: "Group", enabled: true }] },
  "/ids/sources": [],
  "/services/status": { faults: [], av: { available: false, error: "engine unavailable" } },
  "/services/dns": { enabled: false, listenPort: 5353, upstreamServers: ["192.0.2.53"], listenZones: ["lan"], cacheSizeMB: 16 },
  "/services/ntp": { enabled: false, servers: ["ntp.example.test"], intervalSeconds: 90 },
  "/services/syslog": { forwarders: [{ address: "192.0.2.9", port: 6514, proto: "tcp" }], batchSize: 700, flushEvery: 5 },
  "/services/dhcp": { enabled: false, listenIfaces: ["lan"], leaseSeconds: 900, router: "192.0.2.1", dnsServers: ["192.0.2.53"], domain: "example.test", authoritative: true, pools: [{ iface: "lan", start: "192.0.2.100", end: "192.0.2.200" }], reservations: [{ iface: "lan", mac: "00:11:22:33:44:55", ip: "192.0.2.10" }] },
  "/services/av": { enabled: false, mode: "clamav", failPolicy: "closed", clamav: { freshclamEnabled: false, socket: "/run/clamav/clamd.sock" }, scan: { downloadMode: "hold" } },
  "/services/av/defs": { files: [], path: "/data/clamav" },
  "/services/proxy/forward": { enabled: false, listenPort: 3128, listenZones: ["lan"], allowedDomains: ["example.test"], allowedClients: ["192.0.2.0/24"], upstream: "http://192.0.2.8:3128", logRequests: true },
  "/services/proxy/reverse": { enabled: false, sites: [{ name: "existing", listenPort: 8080, backends: ["http://192.0.2.7"], hostnames: ["example.test"], tlsEnabled: false }] },
  "/services/vpn": { wireguard: { enabled: false, interface: "wg0", listenPort: 51820, listenZone: "lan", listenInterfaces: [], addressCIDR: "10.8.0.1/24", privateKey: "private", peers: [{ publicKey: "peer", allowedIPs: ["10.8.0.2/32"] }] }, openvpn: { enabled: false, mode: "client", configPath: "/data/client.ovpn" } },
  "/identities": { mappings: [{ ip: "192.0.2.5", identities: ["operator"] }] },
  "/assets": [],
  "/config/diff": { running: { schema_version: "0.1.9", system: { hostname: "existing" } }, candidate: { schema_version: "0.1.9", system: { hostname: "existing" } }, changed: false, changedSections: [] },
};

async function mockAPI(page: Page) {
  const server = { data: structuredClone(data), counter: 1, failed: new Set<string>(), nullReads: new Set<string>(), writes: [] as { path: string; body: unknown }[] };
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const req = route.request();
    const path = new URL(req.url()).pathname.slice(prefix.length);
    if (path === "/auth/me" || path === "/auth/session") return route.fulfill({ json: { id: "admin", username: "containd", role: "admin" } });
    if (req.method() === "GET") {
      if (server.failed.has(path)) return route.fulfill({ status: 503, json: { error: "unavailable" } });
      return route.fulfill({ json: server.nullReads.has(path) ? null : server.data[path] ?? {}, headers: { "X-Containd-Revision": revision(server.counter) } });
    }
    const body: unknown = req.postDataJSON();
    server.writes.push({ path, body });
    const base = req.headers()["x-containd-if-revision"];
    if (base === undefined) return route.fulfill({ status: 428, json: { error: "revision required", code: "config_revision_required" } });
    if (base.length > 64 || !/^[0-9a-f]{16}\.[1-9][0-9]*$/.test(base)) return route.fulfill({
      status: 400, json: { error: "malformed revision", code: "config_revision_malformed" },
    });
    if (base !== revision(server.counter)) return route.fulfill({
      status: 412, json: { error: "changed", code: "config_revision_mismatch", currentRevision: revision(server.counter) },
    });
    server.data[path] = body;
    return route.fulfill({ json: body, headers: { "X-Containd-Revision": revision(++server.counter), "X-Containd-Config": "staged" } });
  });
  return server;
}

for (const surface of ["raw editor", "restore"] as const) {
  test(`Config ${surface} preserves user keys and displays the full rejection detail`, async ({ page }) => {
    const server = await mockAPI(page);
    server.data["/config/backups"] = [];
    const path = surface === "raw editor" ? "/config/candidate" : "/config/import";
    const detail = 'unknown top-level key "dataPlane" (did you mean "dataplane"?)';
    const document = { schema_version: "0.1.10", dataPlane: { enforcement: true } };
    let submitted: unknown;
    let base: string | undefined;
    await page.route(`**/api/v1${path}`, async (route) => {
      submitted = route.request().postDataJSON();
      base = route.request().headers()["x-containd-if-revision"];
      if (!base) return route.fulfill({ status: 428, json: { error: "revision required", code: "config_revision_required" } });
      if (base !== revision(server.counter)) return route.fulfill({
        status: 412, json: { error: "changed", code: "config_revision_mismatch", currentRevision: revision(server.counter) },
      });
      await route.fulfill({ status: 400, json: { error: "invalid JSON", detail } });
    });
    await Promise.all([
      page.waitForResponse(read("/config/diff")),
      page.goto(surface === "raw editor" ? "/config/?tab=candidate" : "/config/"),
    ]);
    if (surface === "raw editor") {
      const editor = page.getByRole("textbox", { name: "Staged config JSON", exact: true });
      await expect(editor).toBeEnabled();
      await editor.fill(JSON.stringify(document));
      await page.getByRole("button", { name: "Save staged config", exact: true }).click();
      await expect(editor).toHaveValue(JSON.stringify(document));
    } else {
      await page.locator('input[type="file"][accept=".json"]:visible').setInputFiles({
        name: "config.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(document)),
      });
      await page.getByRole("button", { name: "Restore", exact: true }).click();
    }
    const prefix = surface === "raw editor" ? "Failed to save candidate" : "Restore failed";
    await expect(page.getByText(`${prefix}: invalid JSON: ${detail}`, { exact: true })).toBeVisible();
    expect(submitted).toEqual(document);
    expect(base).toBe(revision(server.counter));
  });
}

const services = [
  { name: "DNS", route: "/system/services/dns/", path: "/services/dns", label: "Enable DNS resolver" },
  { name: "NTP", route: "/system/services/ntp/", path: "/services/ntp", label: "Enable NTP client" },
  { name: "AV", route: "/system/services/av/", path: "/services/av", label: "Enable AV/ICAP scanning" },
  { name: "DHCP", route: "/dhcp/", path: "/services/dhcp", label: "Enable DHCP server" },
  { name: "IDS", route: "/ids/", path: "/ids/rules", label: "Enable IDS engine" },
  { name: "VPN", route: "/vpn/", path: "/services/vpn", label: "Enable WireGuard" },
  { name: "Forward proxy", route: "/proxies/", path: "/services/proxy/forward", label: "Enabled", index: 0 },
  { name: "Reverse proxy", route: "/proxies/", path: "/services/proxy/reverse", label: "Enabled", index: 1 },
  { name: "Syslog", route: "/system/services/syslog/", path: "/services/syslog", label: "" },
];

for (const item of services) {
  for (const failure of ["HTTP", "null"] as const) {
    test(`${item.name}: ${failure} reads block saves, preserve refresh drafts, and recover losslessly`, async ({ page }) => {
      const server = await mockAPI(page);
      const failed = failure === "HTTP" ? server.failed : server.nullReads;
      failed.add(item.path);
      await Promise.all([page.waitForResponse(read(item.path)), page.goto(item.route)]);
      const save = page.getByRole("button", { name: "Save", exact: true }).nth(item.index ?? 0);
      await expect(save).toBeDisabled();
      await expect(page.getByRole("alert").filter({ hasText: "Configuration unavailable" })).toContainText("Configuration unavailable");
      expect(server.writes).toEqual([]);
      failed.clear();
      await Promise.all([page.waitForResponse(read(item.path)), page.getByRole("button", { name: "Refresh", exact: true }).first().click()]);
      await expect(save).toBeEnabled();
      const field = item.label ? page.getByRole("checkbox", { name: item.label }).nth(item.index ?? 0) : page.locator('input[type="number"]').first();
      if (item.label) await field.check();
      else await field.fill("701");
      failed.add(item.path);
      // A manual Refresh would discard drafts only if its read succeeded.
      await Promise.all([page.waitForResponse(read(item.path)), page.getByRole("button", { name: "Refresh", exact: true }).first().click()]);
      await expect(save).toBeDisabled();
      await expect(page.getByRole("alert").filter({ hasText: "Configuration unavailable" })).toContainText("Configuration unavailable");
      if (item.label) await expect(field).toBeChecked();
      else await expect(field).toHaveValue("701");
      // Earlier successful toasts may still exist, but the failed refresh must
      // not emit another. Observe the next refresh independently.
      await page.evaluate(() => { (window as unknown as { successes: number }).successes = 0; new MutationObserver((records) => {
        for (const record of records) for (const node of record.addedNodes) if (node.textContent?.includes("status refreshed")) (window as unknown as { successes: number }).successes++;
      }).observe(document.body, { childList: true, subtree: true }); });
      await Promise.all([page.waitForResponse(read(item.path)), page.getByRole("button", { name: "Refresh", exact: true }).first().click()]);
      await expect(save).toBeDisabled();
      expect(await page.evaluate(() => (window as unknown as { successes: number }).successes)).toBe(0);
      expect(server.writes).toEqual([]);
      failed.clear();
      // Subscription recovery does not ask to discard local edits.
      await Promise.all([page.waitForResponse(read(item.path)), page.evaluate((event) => window.dispatchEvent(new CustomEvent(event)), CONFIG_COMMITTED)]);
      await expect(save).toBeEnabled();
      await save.click();
      await expect.poll(() => server.writes.length).toBe(1);
      const original = structuredClone(data[item.path]) as Record<string, unknown>;
      const expected = item.name === "VPN" ? { ...original, wireguard: { ...original.wireguard as object, enabled: true } }
        : item.name === "Syslog" ? { ...original, batchSize: 701 } : { ...original, enabled: true };
      expect(server.writes[0]).toEqual({ path: item.path, body: expected });
    });
  }
}

for (const item of [
  { name: "Routing", route: "/routing/", path: "/routing", button: "Add route" },
  { name: "Zones", route: "/zones/", path: "/zones", button: "Create" },
  { name: "Interfaces", route: "/interfaces/", path: "/interfaces", button: "Create" },
  { name: "Identities", route: "/identities/", path: "/identities", button: "Bind" },
  { name: "Firewall", route: "/firewall/", path: "/dataplane", button: "Quick start (LAN→WAN)" },
  { name: "Config", route: "/config/?tab=candidate", path: "/config/diff", button: "Save staged config" },
]) {
  test(`${item.name} cannot stage configuration after a failed initial read`, async ({ page }) => {
    const server = await mockAPI(page);
    server.failed.add(item.path);
    await Promise.all([page.waitForResponse(read(item.path)), page.goto(item.route)]);
    await expect(page.getByRole("alert").filter({ hasText: "Configuration unavailable" })).toContainText("Configuration unavailable");
    if (item.name === "Routing") await page.getByText("Add static route (advanced)", { exact: true }).click();
    const button = page.getByRole("button", { name: item.button, exact: true });
    await expect(button).toBeDisabled();
    expect(server.writes).toEqual([]);
  });
}

test("stand-in DNS defaults remain disabled until the authoritative subtree loads", async ({ page }) => {
  const server = await mockAPI(page);
  server.failed.add("/services/dns");
  await Promise.all([page.waitForResponse(read("/services/dns")), page.goto("/system/services/dns/")]);
  await expect(page.locator("textarea")).toBeDisabled();
  server.failed.clear();
  await Promise.all([page.waitForResponse(read("/services/dns")), page.evaluate((event) => window.dispatchEvent(new CustomEvent(event)), CONFIG_COMMITTED)]);
  const save = page.getByRole("button", { name: "Save", exact: true });
  await expect(save).toBeEnabled();
  await expect(page.locator("textarea")).toHaveValue("192.0.2.53");
  await save.click();
  await expect.poll(() => server.writes.length).toBe(1);
  expect(server.writes[0]).toEqual({ path: "/services/dns", body: data["/services/dns"] });
});

for (const failure of ["HTTP", "null"] as const) {
  test(`PCAP: ${failure} reads block default saves, preserve drafts, and recover losslessly`, async ({ page }) => {
    const server = await mockAPI(page);
    const failed = failure === "HTTP" ? server.failed : server.nullReads;
    failed.add("/pcap/config");
    await page.clock.setFixedTime(new Date("2026-10-31T12:00:00Z"));
    await Promise.all([page.waitForResponse(read("/pcap/config")), page.goto("/dataplane/")]);
    const save = page.getByRole("button", { name: "Save PCAP defaults", exact: true });
    const error = page.getByRole("alert").filter({ hasText: "Configuration unavailable" });
    const refreshed = page.getByText("Last refreshed:", { exact: false });
    const refresh = page.getByRole("button", { name: "Refresh", exact: true });
    await expect(error).toBeVisible();
    await expect(save).toBeDisabled();
    await expect(refreshed).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Upload PCAP", exact: true })).toBeEnabled();
    expect(server.writes).toEqual([]);

    failed.clear();
    await Promise.all([page.waitForResponse(read("/pcap/config")), refresh.click()]);
    await expect(save).toBeEnabled();
    await expect(error).toHaveCount(0);
    await expect(refreshed).toBeVisible();
    const lastRefresh = await refreshed.textContent();
    await page.getByText("Advanced capture options", { exact: true }).click();
    // The file-prefix input follows its visible label in the advanced section.
    const prefixField = page.locator("label").filter({ hasText: "File prefix" }).locator("..").locator("input");
    await expect(prefixField).toHaveValue("existing");
    await prefixField.fill("draft");
    failed.add("/pcap/config");
    await page.clock.setFixedTime(new Date("2026-10-31T12:01:00Z"));
    await Promise.all([page.waitForResponse(read("/pcap/config")), refresh.click()]);
    await expect(error).toBeVisible();
    await expect(save).toBeDisabled();
    await expect(prefixField).toHaveValue("draft");
    await expect(refreshed).toHaveText(lastRefresh!);
    await expect(page.getByText("PCAP defaults staged", { exact: false })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Start capture now", exact: true })).toBeEnabled();
    expect(server.writes).toEqual([]);

    failed.clear();
    await Promise.all([page.waitForResponse(read("/pcap/config")), page.evaluate((event) => window.dispatchEvent(new CustomEvent(event)), CONFIG_COMMITTED)]);
    await expect(save).toBeEnabled();
    await expect(error).toHaveCount(0);
    await expect(prefixField).toHaveValue("draft");
    await save.click();
    await expect.poll(() => server.writes.length).toBe(1);
    expect(server.writes[0]).toEqual({
      path: "/pcap/config",
      body: { ...data["/pcap/config"] as object, filePrefix: "draft" },
    });
  });
}
