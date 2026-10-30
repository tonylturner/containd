import { expect, test, type Locator, type Page, type Response } from "@playwright/test";
import { CONFIG_COMMITTED, CONFIG_STAGED } from "../lib/config-events";

const prefix = "/api/v1";
const read = (path: string) => (r: Response) =>
  new URL(r.url()).pathname === prefix + path && r.request().method() === "GET";

async function mockAPI(page: Page) {
  const data: Record<string, unknown> = {
    "/zones": [{ name: "wan" }, { name: "lan" }],
    "/interfaces": [{ name: "lan1", alias: "LAN", addresses: ["192.0.2.1/24"] }],
    "/interfaces/state": [],
    "/identities": { mappings: [{ ip: "192.0.2.5", identities: ["operator"] }] },
    "/firewall/rules": [],
    "/dataplane": { captureInterfaces: [], dpiMock: false, dpiEnabled: true, dpiMode: "learn", dpiIcsProtocols: { modbus: true } },
    "/templates/ics": [{ name: "Test baseline", description: "Test template", protocol: "modbus", parameters: [{ name: "codes", label: "Codes", type: "text", placeholder: "3, 16" }] }],
    "/firewall/nat": { enabled: false, portForwards: [] },
    "/routing": { gateways: [], routes: [], rules: [] },
    "/ids/rules": { enabled: false, rules: [{ id: "test-rule", title: "Test rule", enabled: true }] },
    "/ids/sources": [],
    "/services/dns": { enabled: false, upstreamServers: ["192.0.2.53"], listenPort: 53 },
    "/services/ntp": { enabled: false, servers: ["pool.ntp.org"], intervalSeconds: 0 },
    "/services/syslog": { forwarders: [], batchSize: 500, flushEvery: 2 },
    "/services/av": { enabled: false, mode: "clamav", failPolicy: "open" },
    "/services/av/defs": { files: [], path: "/data/clamav" },
    "/services/proxy/forward": { enabled: false, upstream: "", listenZones: [], allowedDomains: [] },
    "/services/proxy/reverse": { enabled: false, sites: [] },
    "/services/vpn": { wireguard: { enabled: false, interface: "wg0", peers: [] }, openvpn: { enabled: false } },
    "/services/status": { av: { available: false, error: "engine unavailable" } },
    "/assets": [],
    "/config/diff": { changed: false, changedSections: [] },
  };
  const server = { data, failedReads: new Set<string>(), failedWrites: new Set<string>(), writes: [] as { path: string; body: unknown }[], hold: null as Promise<void> | null };
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const req = route.request();
    const path = new URL(req.url()).pathname.slice(prefix.length);
    if (path === "/auth/me" || path === "/auth/session") {
      return route.fulfill({ json: { id: "admin", username: "containd", role: "admin" } });
    }
    if (req.method() === "GET") return server.failedReads.has(path)
      ? route.fulfill({ status: 503, json: { error: "unavailable" } })
      : route.fulfill({ json: data[path] ?? {} });
    const body = req.postDataJSON();
    server.writes.push({ path, body });
    if (server.hold) await server.hold;
    if (server.failedWrites.has(path)) return route.fulfill({ status: 400, json: { error: "rejected" } });
    let result = body;
    if (path === "/templates/ics/apply") {
      return route.fulfill({ json: { rules: [], created: 0 }, headers: body.preview ? {} : { "X-Containd-Config": "staged" } });
    }
    if (path === "/firewall/rules" && req.method() === "POST") {
      data[path] = [...data[path] as object[], body];
    } else if (path.startsWith("/firewall/rules/")) {
      const id = decodeURIComponent(path.slice("/firewall/rules/".length));
      const rows = data["/firewall/rules"] as { id: string }[];
      result = { ...rows.find((row) => row.id === id), id, ...body };
      data["/firewall/rules"] = [...rows.filter((row) => row.id !== id), result];
    } else if (path.startsWith("/zones/") || path.startsWith("/interfaces/")) {
      const collection = path.slice(0, path.lastIndexOf("/"));
      const name = decodeURIComponent(path.slice(path.lastIndexOf("/") + 1));
      data[collection] = (data[collection] as { name: string }[]).map((row) =>
        row.name === name ? (result = { ...row, ...body }) : row);
    } else if (path === "/identities") {
      data[path] = { mappings: [...(data[path] as { mappings: { ip: string }[] }).mappings.filter((row) => row.ip !== body.ip), body] };
    } else data[path] = body;
    await route.fulfill({ json: result, headers: { "X-Containd-Config": "staged" } });
  });
  return server;
}

async function open(page: Page, route: string, path: string) {
  await Promise.all([page.waitForResponse(read(path)), page.goto(route)]);
}

async function announce(page: Page, path: string, event = CONFIG_COMMITTED) {
  await Promise.all([
    page.waitForResponse(read(path)),
    page.evaluate((name) => window.dispatchEvent(new CustomEvent(name)), event),
  ]);
}

type TextPage = {
  name: string; route: string; path: string;
  field: (page: Page) => Locator;
  prepare?: (page: Page) => Promise<void>;
  first: string; later: string;
};
const textPages: TextPage[] = [
  { name: "DNS", route: "/system/services/dns/", path: "/services/dns", field: (p) => p.locator("textarea"), first: "192.0.2.53\n192.0.2.54\n", later: "192.0.2.53\n192.0.2.", },
  { name: "NTP", route: "/system/services/ntp/", path: "/services/ntp", field: (p) => p.locator("textarea"), first: "pool.ntp.org\nntp.lab\n", later: "pool.ntp.org\nntp.", },
  { name: "Syslog", route: "/system/services/syslog/", path: "/services/syslog", field: (p) => p.locator('input[type="number"]').first(), first: "700", later: "701" },
  { name: "AV", route: "/system/services/av/", path: "/services/av", field: (p) => p.getByPlaceholder("/run/clamav/clamd.sock"), first: "/data/clamd.sock", later: "/data/clamd-new.sock" },
  { name: "Proxies", route: "/proxies/", path: "/services/proxy/forward", field: (p) => p.getByPlaceholder("mgmt, lan"), prepare: async (p) => { await p.getByText("Advanced options", { exact: true }).first().click(); }, first: "lan, ", later: "lan, wan, " },
  { name: "VPN", route: "/vpn/", path: "/services/vpn", field: (p) => p.locator("textarea").first(), first: "[] ", later: "[ " },
];

for (const item of textPages) {
  test(`${item.name} keeps edits through subscription and its staged save, including later typing`, async ({ page }) => {
    const server = await mockAPI(page);
    await open(page, item.route, item.path);
    await item.prepare?.(page);
    const field = item.field(page);
    await expect(field).toBeVisible();
    await field.fill(item.first);
    server.data[item.path] = item.name === "VPN"
      ? { wireguard: { enabled: true, interface: "wg0", peers: [] }, openvpn: { enabled: false } }
      : { ...(server.data[item.path] as object), enabled: true };
    await announce(page, item.path);
    await expect(page.getByRole("status", { name: "Unsaved edits" }).first()).toContainText("changed on the server");
    await expect(field).toHaveValue(item.first);
    // Hold the save echo, not just a synthetic event: the request helper will
    // dispatch CONFIG_STAGED and cause a real subscription read on release.
    let release!: () => void;
    server.hold = new Promise<void>((resolve) => { release = resolve; });
    await page.getByRole("button", { name: "Save", exact: true }).first().click();
    await expect.poll(() => server.writes.length).toBe(1);
    await field.fill(item.later);
    const refreshed = page.waitForResponse(read(item.path));
    release();
    await refreshed;
    await expect(field).toHaveValue(item.later);
    expect(server.writes[0].path).toBe(item.path);
    if (item.name === "DNS") expect(server.writes[0].body).toMatchObject({ upstreamServers: ["192.0.2.53", "192.0.2.54"] });
    if (item.name === "NTP") expect(server.writes[0].body).toMatchObject({ servers: ["pool.ntp.org", "ntp.lab"] });
    if (item.name === "Proxies") expect(server.writes[0].body).toMatchObject({ listenZones: ["lan"] });
    if (item.name === "VPN") expect(server.writes[0].body).toMatchObject({ wireguard: { peers: [] } });
    await page.getByRole("button", { name: "Refresh", exact: true }).first().click();
    await expect(field).not.toHaveValue(item.later);
  });
}

test("IDS retains a rule modal draft through a staged save and a deleted server rule", async ({ page }) => {
  const server = await mockAPI(page);
  await open(page, "/ids/", "/ids/rules");
  let release!: () => void;
  server.hold = new Promise<void>((resolve) => { release = resolve; });
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => server.writes.length).toBe(1);
  await page.getByRole("button", { name: "Edit", exact: true }).first().click();
  const field = page.locator("textarea");
  await field.fill('{"id":"test-rule", "title":');
  server.data["/ids/rules"] = { enabled: true, rules: [] };
  await announce(page, "/ids/rules");
  await expect(field).toHaveValue('{"id":"test-rule", "title":');
  await expect(page.getByRole("status", { name: "Unsaved edits" })).toContainText("changed on the server");
  // The save submitted before the modal opened cannot acknowledge its draft.
  const refreshed = page.waitForResponse(read("/ids/rules"));
  release();
  await refreshed;
  await expect(field).toHaveValue('{"id":"test-rule", "title":');
});

for (const item of [
  { name: "Zones", route: "/zones/", path: "/zones", field: (p: Page) => p.getByPlaceholder("name (e.g. ot)"), row: "wan" },
  { name: "Interfaces", route: "/interfaces/", path: "/interfaces", field: (p: Page) => p.getByPlaceholder("name (e.g. tunnel1)"), row: "lan1" },
  { name: "Identities", route: "/identities/", path: "/identities", field: (p: Page) => p.getByRole("textbox", { name: "Identities", exact: true }), row: "192.0.2.5" },
]) {
  test(`${item.name} keeps creation and row edits through refresh, removal and another row save`, async ({ page }) => {
    const server = await mockAPI(page);
    await open(page, item.route, item.path);
    const field = item.field(page);
    await field.fill("unfinished, ");
    const row = page.getByRole("row").filter({ has: page.getByRole("cell", { name: item.row, exact: true }) });
    await row.getByRole("button", { name: "Edit", exact: true }).click();
    const rowField = row.getByRole("textbox").first();
    await rowField.fill("row draft, ");
    server.data[item.path] = item.name === "Identities" ? { mappings: [] } : [];
    await announce(page, item.path);
    await expect(field).toHaveValue("unfinished, ");
    await expect(rowField).toHaveValue("row draft, ");
    await expect(page.getByRole("status", { name: "Unsaved edits" })).toContainText("changed on the server");
    // Reintroduce the row, then save it while the independent creation form
    // is unfinished. Its staged refresh must not reset that creation form.
    server.data[item.path] = item.name === "Identities"
      ? { mappings: [{ ip: item.row, identities: ["operator"] }] } : [{ name: item.row }];
    await announce(page, item.path, CONFIG_STAGED);
    await rowField.fill(item.name === "Identities" ? "supervisor" : "Saved row");
    await Promise.all([
      page.waitForResponse(read(item.path)),
      row.getByRole("button", { name: "Save", exact: true }).click(),
    ]);
    await expect.poll(() => server.writes.length).toBe(1);
    await expect(field).toHaveValue("unfinished, ");
    await page.getByRole("button", { name: "Refresh", exact: true }).first().click();
    await expect(field).toHaveValue("");
  });
}

test("Routing keeps an unfinished gateway while staging a route", async ({ page }) => {
  const server = await mockAPI(page);
  await open(page, "/routing/", "/routing");
  await page.getByText("Add gateway (advanced)", { exact: true }).click();
  const field = page.getByPlaceholder("isp1");
  await field.fill("gateway draft");
  server.data["/routing"] = { gateways: [{ name: "other", address: "192.0.2.1" }], routes: [], rules: [] };
  await announce(page, "/routing");
  await expect(field).toHaveValue("gateway draft");
  await expect(page.getByRole("status", { name: "Unsaved edits" })).toContainText("changed on the server");
  await page.getByText("Add static route (advanced)", { exact: true }).click();
  await page.getByPlaceholder("dst (CIDR or default)").fill("198.51.100.0/24");
  await page.getByRole("button", { name: "Add route", exact: true }).click();
  await expect.poll(() => server.writes.length).toBe(1);
  await expect(field).toHaveValue("gateway draft");
  await page.getByRole("button", { name: "Refresh", exact: true }).first().click();
  await expect(field).toHaveValue("");
});

test("Wizard keeps its active step and raw text on committed and staged notifications", async ({ page }) => {
  const server = await mockAPI(page);
  await open(page, "/wizard/", "/firewall/nat");
  await page.getByRole("button", { name: /Publish Internal Service/ }).click();
  const field = page.getByPlaceholder("e.g. 192.168.1.10");
  await field.fill("192.0.");
  server.data["/firewall/nat"] = { enabled: true };
  for (const event of [CONFIG_COMMITTED, CONFIG_STAGED]) {
    await announce(page, "/firewall/nat", event);
    await expect(field).toHaveValue("192.0.");
    await expect(page.getByRole("status", { name: "Unsaved edits" })).toContainText("changed on the server");
  }
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(field).toHaveCount(0);
});

test("NAT keeps both cards and unfinished DNAT fields when SNAT is staged", async ({ page }) => {
  const server = await mockAPI(page);
  await open(page, "/nat/", "/firewall/nat");
  const field = page.getByPlaceholder("dest ip");
  await field.fill("192.0.");
  await page.getByRole("button", { name: "Off", exact: true }).click();
  server.data["/firewall/nat"] = { enabled: false, egressZone: "wan", portForwards: [] };
  await announce(page, "/firewall/nat");
  await expect(field).toHaveValue("192.0.");
  await expect(page.getByRole("button", { name: "On", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Save NAT", exact: true }).click();
  await expect.poll(() => server.writes.length).toBe(1);
  await expect(field).toHaveValue("192.0.");
  await page.getByRole("button", { name: "Refresh", exact: true }).first().click();
  await expect(field).toHaveValue("");
});

test("DNS automatic refresh keeps raw-only edits", async ({ page }) => {
  const server = await mockAPI(page);
  await open(page, "/system/services/dns/", "/services/dns");
  const field = page.locator("textarea");
  await expect(field).toHaveValue("192.0.2.53");
  await field.fill("192.0.2.53\n");
  await page.clock.install();
  await page.getByRole("checkbox", { name: "Auto", exact: true }).check();
  server.data["/services/dns"] = { enabled: true, upstreamServers: ["192.0.2.54"] };
  await Promise.all([page.waitForResponse(read("/services/dns")), page.clock.fastForward(15_000)]);
  await expect(page.getByRole("status", { name: "Unsaved edits" })).toContainText("changed on the server");
  await expect(field).toHaveValue("192.0.2.53\n");
});

test("a row save keeps later typing and another deleted row's draft, including dotted names", async ({ page }) => {
  const server = await mockAPI(page);
  server.data["/zones"] = [{ name: "lan" }, { name: "lan.prod" }];
  await open(page, "/zones/", "/zones");
  const row = (name: string) => page.getByRole("row").filter({ has: page.getByRole("cell", { name, exact: true }) });
  for (const name of ["lan", "lan.prod"]) {
    await row(name).getByRole("button", { name: "Edit", exact: true }).click();
    await row(name).getByRole("textbox").first().fill(`${name} draft`);
  }
  let release!: () => void;
  server.hold = new Promise<void>((resolve) => { release = resolve; });
  await row("lan").getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => server.writes.length).toBe(1);
  await row("lan").getByRole("button", { name: "Edit", exact: true }).click();
  await row("lan").getByRole("textbox").first().fill("later typing");
  server.data["/zones"] = [{ name: "lan" }];
  await announce(page, "/zones");
  const refreshed = page.waitForResponse(read("/zones"));
  release();
  await refreshed;
  await expect(row("lan").getByRole("textbox").first()).toHaveValue("later typing");
  await expect(row("lan.prod").getByRole("textbox").first()).toHaveValue("lan.prod draft");
});

test("a creation save cannot clear typing that happened after submission", async ({ page }) => {
  const server = await mockAPI(page);
  await open(page, "/identities/", "/identities");
  await page.getByRole("textbox", { name: "Address", exact: true }).fill("192.0.2.9");
  const labels = page.getByRole("textbox", { name: "Identities", exact: true });
  await labels.fill("operator");
  let release!: () => void;
  server.hold = new Promise<void>((resolve) => { release = resolve; });
  await page.getByRole("button", { name: "Bind", exact: true }).click();
  await expect.poll(() => server.writes.length).toBe(1);
  await labels.fill("operator, ");
  const refreshed = page.waitForResponse(read("/identities"));
  release();
  await refreshed;
  await expect(page.getByRole("button", { name: "Bind", exact: true })).toBeEnabled();
  await expect(labels).toHaveValue("operator, ");
});

test("NAT retains disabled drafts across an unavailable refresh and recovery", async ({ page }) => {
  const server = await mockAPI(page);
  await open(page, "/nat/", "/firewall/nat");
  const field = page.getByPlaceholder("dest ip");
  await field.fill("192.0.");
  server.failedReads.add("/firewall/nat");
  await announce(page, "/firewall/nat");
  await expect(field).toBeDisabled();
  await expect(field).toHaveValue("192.0.");
  server.failedReads.clear();
  await announce(page, "/firewall/nat");
  await expect(field).toBeEnabled();
  await expect(field).toHaveValue("192.0.");
});

test("a forward-proxy staged save does not parse or clear a new reverse site's CSV text", async ({ page }) => {
  const server = await mockAPI(page);
  await open(page, "/proxies/", "/services/proxy/reverse");
  const backends = page.getByPlaceholder("backends host:port, host:port");
  const hosts = page.getByPlaceholder("hostnames (optional)");
  await backends.pressSequentially("srv:80, ");
  await hosts.pressSequentially("lab., ");
  server.data["/services/proxy/reverse"] = { enabled: true, sites: [] };
  await announce(page, "/services/proxy/reverse");
  await expect(page.getByRole("status", { name: "Unsaved edits" })).toContainText("changed on the server");
  await Promise.all([
    page.waitForResponse(read("/services/proxy/reverse")),
    page.getByRole("button", { name: "Save", exact: true }).first().click(),
  ]);
  await expect(backends).toHaveValue("srv:80, ");
  await expect(hosts).toHaveValue("lab., ");
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(backends).toHaveValue("");
});

test("IDS page Save does not acknowledge an unfinished group form", async ({ page }) => {
  const server = await mockAPI(page);
  await open(page, "/ids/", "/ids/rules");
  await page.getByRole("button", { name: /^Groups/ }).click();
  const name = page.getByPlaceholder("e.g. ICS/Modbus");
  await name.fill("new group ");
  server.data["/ids/rules"] = { enabled: true, rules: [] };
  await announce(page, "/ids/rules");
  await Promise.all([
    page.waitForResponse(read("/ids/rules")),
    page.getByRole("button", { name: "Save", exact: true }).click(),
  ]);
  await expect(name).toHaveValue("new group ");
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(name).toHaveValue("");
});

test("NAT does not silently replace a chosen ingress zone removed by a refresh", async ({ page }) => {
  const server = await mockAPI(page);
  await open(page, "/nat/", "/firewall/nat");
  const ingress = page.getByRole("combobox", { name: "Ingress zone" });
  await ingress.selectOption("lan");
  server.data["/zones"] = [{ name: "wan" }];
  await announce(page, "/firewall/nat");
  await expect(ingress).toHaveValue("lan");
  await expect(ingress.getByRole("option", { selected: true })).toHaveText("ingress:lan (no longer on server)");
  await page.getByRole("button", { name: "Add", exact: true }).click();
  await expect(page.getByText("Ingress zone is no longer available. Choose a configured zone.", { exact: true })).toBeVisible();
  expect(server.writes).toHaveLength(0);
});

test("OpenVPN CSV inputs keep trailing separators and parse only their save snapshot", async ({ page }) => {
  const server = await mockAPI(page);
  server.data["/services/vpn"] = { wireguard: { enabled: false }, openvpn: { enabled: false, mode: "server", server: {} } };
  await open(page, "/vpn/", "/services/vpn");
  const dns = page.getByPlaceholder("1.1.1.1, 8.8.8.8");
  const routes = page.getByPlaceholder("192.168.0.0/24, 10.0.0.0/8");
  await dns.pressSequentially("192.0.2.53, ");
  await routes.pressSequentially("192.0.2.0/24, ");
  await announce(page, "/services/vpn");
  await expect(dns).toHaveValue("192.0.2.53, ");
  await expect(routes).toHaveValue("192.0.2.0/24, ");
  let release!: () => void;
  server.hold = new Promise<void>((resolve) => { release = resolve; });
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => server.writes.length).toBe(1);
  await dns.fill("192.0.2.53, 192.");
  const refreshed = page.waitForResponse(read("/services/vpn"));
  release();
  await refreshed;
  await expect(dns).toHaveValue("192.0.2.53, 192.");
  expect(server.writes[0].body).toMatchObject({ openvpn: { server: { pushDNS: ["192.0.2.53"], pushRoutes: ["192.0.2.0/24"] } } });
});

const draftRule = { id: "ot-rule", description: "Original", action: "ALLOW", ics: { protocol: "modbus", functionCode: [3], mode: "learn" } };

for (const surface of ["Firewall", "ICS"]) {
  test(`${surface} modal keeps raw edits across server removal and a save echo with later typing`, async ({ page }) => {
    const server = await mockAPI(page);
    server.data["/firewall/rules"] = [draftRule];
    await open(page, surface === "Firewall" ? "/firewall/" : "/ics/", "/firewall/rules");
    await page.getByRole("row").filter({ hasText: "ot-rule" }).getByRole("button", { name: "Edit", exact: true }).click();
    const input = surface === "Firewall" ? page.getByPlaceholder("sources CIDR (csv)").last()
      : page.getByPlaceholder("3, 16");
    const raw = surface === "Firewall" ? "192.0.2.0/24, " : "3, ";
    await input.fill(raw);
    server.data["/firewall/rules"] = [];
    for (const event of [CONFIG_STAGED, CONFIG_COMMITTED]) {
      await announce(page, "/firewall/rules", event);
      await expect(input).toHaveValue(raw);
      await expect(page.getByRole("status", { name: "Unsaved edits" }).first()).toBeVisible();
    }
    let release!: () => void;
    server.hold = new Promise<void>((resolve) => { release = resolve; });
    await page.getByRole("button", { name: surface === "Firewall" ? "Save changes" : "Save filter", exact: true }).click();
    await expect.poll(() => server.writes.length).toBe(1);
    await input.fill(raw + (surface === "Firewall" ? "198.51." : "16,"));
    const refreshed = page.waitForResponse(read("/firewall/rules"));
    release();
    await refreshed;
    await expect(input).toHaveValue(raw + (surface === "Firewall" ? "198.51." : "16,"));
    expect(server.writes[0].body).toMatchObject(surface === "Firewall" ? { sources: ["192.0.2.0/24"] } : { ics: { functionCode: [3] } });
    await page.getByRole("button", { name: "Refresh", exact: true }).press("Enter");
    await expect(input).toHaveCount(surface === "Firewall" ? 1 : 0);
    if (surface === "Firewall") await expect(input).toHaveValue("");
  });
}

test("Firewall creation keeps failed submissions and later typing, independently of collection refreshes", async ({ page }) => {
  const server = await mockAPI(page);
  await open(page, "/firewall/", "/firewall/rules");
  const id = page.getByPlaceholder("id (e.g. mb-allow)");
  const sources = page.getByPlaceholder("sources CIDR (csv)");
  await id.fill("new-rule");
  await sources.fill("192.0.2.0/24, ");
  const sourceZone = page.getByRole("combobox").filter({ has: page.getByRole("option", { name: "Source zone (any)", exact: true }) });
  await sourceZone.selectOption("lan");
  server.data["/zones"] = [{ name: "wan" }];
  server.data["/firewall/rules"] = [draftRule];
  await announce(page, "/firewall/rules");
  await expect(page.getByRole("row").filter({ hasText: "ot-rule" })).toBeVisible();
  await expect(sources).toHaveValue("192.0.2.0/24, ");
  await expect(sourceZone).toHaveValue("lan");
  await expect(sourceZone.getByRole("option", { selected: true })).toContainText("no longer on server");
  server.failedWrites.add("/firewall/rules");
  await page.getByRole("button", { name: "Create rule", exact: true }).click();
  await expect(page.getByText("rejected", { exact: true })).toBeVisible();
  await expect(id).toHaveValue("new-rule");
  await expect(sources).toHaveValue("192.0.2.0/24, ");
  server.failedWrites.clear();
  let release!: () => void;
  server.hold = new Promise<void>((resolve) => { release = resolve; });
  await page.getByRole("button", { name: "Create rule", exact: true }).click();
  await expect.poll(() => server.writes.length).toBe(2);
  await sources.fill("192.0.2.0/24, 198.51.");
  release();
  await expect(id).toHaveValue("");
  await expect(sources).toHaveValue("192.0.2.0/24, 198.51.");
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(sources).toHaveValue("");
});

test("Firewall DPI parsing and unfinished exclusions survive background refresh and failed saves", async ({ page }) => {
  const server = await mockAPI(page);
  await open(page, "/firewall/", "/dataplane");
  await page.getByRole("button", { name: "Configure", exact: true }).first().click();
  const parsing = page.getByRole("combobox", { name: "Modbus/TCP parsing" });
  await parsing.selectOption("strict");
  server.data["/dataplane"] = { ...server.data["/dataplane"] as object, dpiMode: "enforce" };
  await announce(page, "/dataplane");
  await expect(parsing).toHaveValue("strict");
  await expect(page.getByRole("status", { name: "Unsaved edits" })).toBeVisible();
  server.failedWrites.add("/dataplane");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByText("Not saved: rejected")).toBeVisible();
  await expect(parsing).toHaveValue("strict");
  server.failedWrites.clear();
  let release!: () => void;
  server.hold = new Promise<void>((resolve) => { release = resolve; });
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => server.writes.length).toBe(2);
  await parsing.selectOption("tolerant");
  release();
  await expect(page.getByRole("button", { name: "Save", exact: true })).toBeEnabled();
  await expect(parsing).toHaveValue("tolerant");
  expect(server.writes[1].body).toMatchObject({ dpiMode: "enforce", dpiIcsParsing: { modbus: "strict" } });
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  await page.getByRole("button", { name: "Add Exclusion", exact: true }).click();
  const reason = page.getByPlaceholder("Reason (optional)");
  await reason.fill("unfinished, ");
  server.data["/dataplane"] = { ...server.data["/dataplane"] as object, dpiMode: "learn" };
  await announce(page, "/dataplane");
  await expect(reason).toHaveValue("unfinished, ");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(reason).toHaveValue("unfinished, ");
  await page.getByRole("button", { name: "Refresh", exact: true }).press("Enter");
  await expect(reason).toHaveCount(0);
});

test("Templates keep parameters and zone selections through preview, notifications and later stage typing", async ({ page }) => {
  const server = await mockAPI(page);
  await open(page, "/templates/", "/templates/ics");
  await page.getByRole("button", { name: "Generate Rules" }).click();
  const codes = page.getByPlaceholder("3, 16");
  await codes.fill("3, ");
  await page.getByRole("button", { name: "lan", exact: true }).first().click();
  server.data["/zones"] = [{ name: "wan" }, { name: "dmz" }];
  server.data["/templates/ics"] = [{ name: "Test baseline", description: "Changed template", protocol: "modbus", parameters: [] }];
  for (const event of [CONFIG_STAGED, CONFIG_COMMITTED]) {
    await announce(page, "/zones", event);
    await expect(codes).toHaveValue("3, ");
    await expect(page.getByRole("status", { name: "Unsaved edits" })).toBeVisible();
  }
  await expect(page.getByRole("button", { name: "lan (no longer on server)", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Preview", exact: true }).click();
  await expect(page.getByText("Preview: 0 Rule(s)")).toBeVisible();
  await expect(codes).toHaveValue("3, ");
  server.failedWrites.add("/templates/ics/apply");
  await page.getByRole("button", { name: "Stage", exact: true }).click();
  await expect(page.getByText("Failed to apply template.", { exact: true })).toBeVisible();
  await expect(codes).toHaveValue("3, ");
  server.failedWrites.clear();
  let release!: () => void;
  server.hold = new Promise<void>((resolve) => { release = resolve; });
  await page.getByRole("button", { name: "Stage", exact: true }).click();
  await expect.poll(() => server.writes.length).toBe(3);
  await codes.fill("3, 16, ");
  release();
  await expect(page.getByRole("button", { name: "Stage", exact: true })).toBeEnabled();
  await expect(codes).toHaveValue("3, 16, ");
  expect(server.writes[2].body).toMatchObject({ parameters: { codes: "3, " }, sourceZones: ["lan"] });
  await page.getByRole("button", { name: "Refresh", exact: true }).press("Enter");
  await expect(codes).toHaveCount(0);
});


for (const surface of ["Firewall", "ICS"]) {
  test(`${surface} pristine modal adopts the new server copy without an unsaved warning`, async ({ page }) => {
    const server = await mockAPI(page);
    server.data["/firewall/rules"] = [draftRule];
    await open(page, surface === "Firewall" ? "/firewall/" : "/ics/", "/firewall/rules");
    await page.getByRole("row").filter({ hasText: "ot-rule" }).getByRole("button", { name: "Edit", exact: true }).click();
    server.data["/firewall/rules"] = [{ ...draftRule, description: "New server copy", ics: { ...draftRule.ics, functionCode: [16] } }];
    await announce(page, "/firewall/rules");
    const input = surface === "Firewall" ? page.getByPlaceholder("description").last() : page.getByPlaceholder("3, 16");
    await expect(input).toHaveValue(surface === "Firewall" ? "New server copy" : "16");
    await expect(page.getByRole("status", { name: "Unsaved edits" })).toHaveCount(0);
  });
}

test("Firewall IT decoder draft survives a refresh and acknowledges only the submitted snapshot", async ({ page }) => {
  const server = await mockAPI(page);
  await open(page, "/firewall/", "/dataplane");
  await page.getByRole("button", { name: "Configure", exact: true }).nth(1).click();
  const modal = page.locator("div.fixed").filter({ has: page.getByRole("heading", { name: "IT Protocol DPI Configuration" }) });
  await modal.getByRole("button", { name: "Disable All", exact: true }).click();
  server.data["/dataplane"] = { ...server.data["/dataplane"] as object, dpiMode: "enforce" };
  await announce(page, "/dataplane");
  await expect(modal.getByRole("status", { name: "Unsaved edits" })).toBeVisible();
  let release!: () => void;
  server.hold = new Promise<void>((resolve) => { release = resolve; });
  await modal.getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => server.writes.length).toBe(1);
  await modal.getByRole("button", { name: "Enable All", exact: true }).click();
  release();
  await expect(modal.getByRole("button", { name: "Save", exact: true })).toBeEnabled();
  expect(server.writes[0].body).toMatchObject({ dpiProtocols: { http: false }, dpiMode: "enforce" });
  await modal.getByRole("button", { name: "Save", exact: true }).click();
  await expect(modal).toHaveCount(0);
  expect(server.writes[1].body).toMatchObject({ dpiProtocols: { http: true } });
});
