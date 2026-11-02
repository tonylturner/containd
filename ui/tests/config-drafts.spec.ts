import { expect, test, type Locator, type Page, type Response } from "@playwright/test";
import { CONFIG_COMMITTED, CONFIG_STAGED } from "../lib/config-events";

const prefix = "/api/v1";
const revision = (counter: number) => `0123456789abcdef.${counter}`;
const read = (path: string) => (r: Response) =>
  new URL(r.url()).pathname === prefix + path && r.request().method() === "GET";

async function mockAPI(page: Page) {
  const data: Record<string, unknown> = {
    "/zones": [{ name: "wan" }, { name: "lan" }],
    "/interfaces": [{ name: "lan1", alias: "LAN", addresses: ["192.0.2.1/24"] }],
    "/interfaces/state": [],
    "/identities": { mappings: [{ ip: "192.0.2.5", identities: ["operator"] }] },
    "/firewall/rules": [],
    "/dataplane": { captureInterfaces: [], dpiMock: false, dpiEnabled: true, dpiMode: "monitor", dpiIcsProtocols: { modbus: true } },
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
    "/services/status": { faults: [], av: { available: false, error: "engine unavailable" } },
    "/assets": [],
    "/config/diff": { changed: false, changedSections: [] },
  };
  const server = {
    data, counter: 1, failedReads: new Set<string>(), failedWrites: new Set<string>(),
    writes: [] as { path: string; body: unknown }[],
    attempts: [] as { path: string; revision?: string; status: number }[],
    hold: null as Promise<void> | null,
    change(path: string, value: unknown) { data[path] = value; this.counter++; },
  };
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
      : route.fulfill({ json: data[path] ?? {}, headers: { "X-Containd-Revision": revision(server.counter) } });
    const body = req.postDataJSON();
    server.writes.push({ path, body });
    const base = req.headers()["x-containd-if-revision"];
    const attempt = { path, revision: base, status: 200 };
    server.attempts.push(attempt);
    if (path === "/templates/ics/apply" && body.preview) {
      return route.fulfill({ json: { rules: [], created: 0 } });
    }
    if (base === undefined) {
      attempt.status = 428;
      return route.fulfill({ status: 428, json: { error: "revision required", code: "config_revision_required" } });
    }
    if (base.length > 64 || !/^[0-9a-f]{16}\.[1-9][0-9]*$/.test(base)) {
      attempt.status = 400;
      return route.fulfill({ status: 400, json: { error: "malformed revision", code: "config_revision_malformed" } });
    }
    if (base !== revision(server.counter)) {
      attempt.status = 412;
      return route.fulfill({ status: 412, json: { error: "changed", code: "config_revision_mismatch", currentRevision: revision(server.counter) } });
    }
    if (server.failedWrites.has(path)) {
      attempt.status = 400;
      return route.fulfill({ status: 400, json: { error: "rejected" } });
    }
    let result = body;
    if (path === "/templates/ics/apply") {
      result = { rules: [], created: 0 };
    } else if (path === "/firewall/port-forwards" && req.method() === "POST") {
      const nat = data["/firewall/nat"] as { portForwards?: unknown[] };
      data["/firewall/nat"] = { ...nat, portForwards: [...(nat.portForwards ?? []), body.forward] };
      result = { forward: body.forward, placement: { reason: "generated", rule: { id: "generated-allow" }, index: 0 } };
    } else if (path === "/firewall/rules" && req.method() === "POST") {
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
    // Persist atomically before delaying the acknowledgement. A concurrent read
    // can observe this write, and a later external change cannot rewrite its receipt.
    const acknowledgedRevision = revision(++server.counter);
    if (server.hold) await server.hold;
    await route.fulfill({ json: result, headers: { "X-Containd-Revision": acknowledgedRevision, "X-Containd-Config": "staged" } });
  });
  return server;
}

async function reviewConflict(page: Page, server: Awaited<ReturnType<typeof mockAPI>>, save: Locator, scope: Page | Locator = page) {
  const counter = server.counter;
  const before = structuredClone(server.data);
  const response = page.waitForResponse(r => r.status() === 412 && r.request().method() !== "GET");
  await save.click();
  expect((await response).status()).toBe(412);
  const alert = scope.getByRole("alert").filter({ hasText: "Configuration changed since you loaded it" });
  await expect(alert).toBeVisible();
  await expect(alert.getByRole("button", { name: "Reload", exact: true })).toBeVisible();
  expect(server.counter).toBe(counter);
  expect(server.data).toEqual(before);
  expect(server.attempts.at(-1)).toMatchObject({ status: 412 });
  expect(server.attempts.at(-1)?.revision).not.toBe(revision(counter));
  const attempts = server.attempts.length;
  await alert.getByRole("button", { name: "Keep my edits", exact: true }).click();
  await expect(scope.getByText("Based on an older view — review, then save again.", { exact: true })).toBeVisible();
  expect(server.attempts).toHaveLength(attempts);
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

test("draft mock enforces preconditions, advances successful writes and external changes, and exempts preview", async ({ page }) => {
  const server = await mockAPI(page);
  await open(page, "/system/services/dns/", "/services/dns");
  const post = (base?: string, path = "/services/dns", body: unknown = { enabled: true }) =>
    page.evaluate(async ({ base, path, body }) => {
      const response = await fetch(`/api/v1${path}`, {
        method: "POST", headers: { "Content-Type": "application/json", ...(base === undefined ? {} : { "X-Containd-If-Revision": base }) },
        body: JSON.stringify(body),
      });
      return { status: response.status, revision: response.headers.get("X-Containd-Revision"), body: await response.json() };
    }, { base, path, body });
  expect(await post()).toMatchObject({ status: 428, revision: null, body: { code: "config_revision_required" } });
  expect(await post("")).toMatchObject({ status: 400, revision: null, body: { code: "config_revision_malformed" } });
  expect(await post("malformed")).toMatchObject({ status: 400, revision: null, body: { code: "config_revision_malformed" } });
  expect(server.counter).toBe(1);
  expect(await post(revision(1))).toMatchObject({ status: 200, revision: revision(2) });
  expect(await post(revision(1))).toMatchObject({ status: 412, revision: null, body: { currentRevision: revision(2) } });
  expect(server.counter).toBe(2);
  server.change("/services/dns", { enabled: false });
  expect(await post(revision(2))).toMatchObject({ status: 412, body: { currentRevision: revision(3) } });
  expect(server.data["/services/dns"]).toEqual({ enabled: false });
  expect(await post(undefined, "/templates/ics/apply", { preview: true })).toMatchObject({ status: 200, revision: null });
  expect(server.counter).toBe(3);
  expect(await post(revision(3))).toMatchObject({ status: 200, revision: revision(4) });
});

for (const item of [
  { name: "DNS", route: "/system/services/dns/", path: "/services/dns", label: "Enable DNS resolver" },
  { name: "NTP", route: "/system/services/ntp/", path: "/services/ntp", label: "Enable NTP client" },
  { name: "AV", route: "/system/services/av/", path: "/services/av", label: "Enable AV/ICAP scanning" },
  { name: "VPN", route: "/vpn/", path: "/services/vpn", label: "Enable WireGuard" },
  { name: "IDS", route: "/ids/", path: "/ids/rules", label: "Enable intrusion detection" },
]) {
  test(`${item.name} keeps a reversion to the old server value during an outstanding save`, async ({ page }) => {
    const server = await mockAPI(page);
    await open(page, item.route, item.path);
    const enabled = page.getByRole("checkbox", { name: item.label });
    await expect(enabled).not.toBeChecked();
    await enabled.check();
    let release!: () => void;
    server.hold = new Promise<void>((resolve) => { release = resolve; });
    await page.getByRole("button", { name: "Save", exact: true }).click();
    await expect.poll(() => server.writes.length).toBe(1);
    await enabled.uncheck();
    // A read of the submitted value arrives before the save acknowledgement.
    await announce(page, item.path);
    await expect(enabled).not.toBeChecked();
    const refreshed = page.waitForResponse(read(item.path));
    release();
    await refreshed;
    await expect(enabled).not.toBeChecked();
    // It remains an unsaved change, not just a temporarily retained value.
    server.hold = null;
    await page.getByRole("button", { name: "Save", exact: true }).click();
    await expect.poll(() => server.writes.length).toBe(2);
    expect(server.writes[1].body).toMatchObject(item.name === "VPN"
      ? { wireguard: { enabled: false } } : { enabled: false });
  });
}

test("a row reversion to its derived value remains explicit while its save is outstanding", async ({ page }) => {
  const server = await mockAPI(page);
  server.data["/zones"] = [{ name: "lan", alias: "Original" }];
  await open(page, "/zones/", "/zones");
  const row = page.getByRole("row").filter({ has: page.getByRole("cell", { name: "lan", exact: true }) });
  await row.getByRole("button", { name: "Edit", exact: true }).click();
  await row.getByRole("textbox").first().fill("Submitted");
  let release!: () => void;
  server.hold = new Promise<void>((resolve) => { release = resolve; });
  await row.getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => server.writes.length).toBe(1);
  await row.getByRole("button", { name: "Edit", exact: true }).click();
  const alias = row.getByRole("textbox").first();
  await alias.fill("Original");
  await announce(page, "/zones");
  const refreshed = page.waitForResponse(read("/zones"));
  release();
  await refreshed;
  await expect(alias).toHaveValue("Original");
  server.hold = null;
  await row.getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => server.writes.length).toBe(2);
  expect(server.writes[1].body).toMatchObject({ alias: "Original" });
});

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
  { name: "AV", route: "/system/services/av/", path: "/services/av", field: (p) => p.getByPlaceholder("/run/clamav/clamd.sock"), prepare: async (p) => { await p.getByText("Advanced local scanner settings", { exact: true }).click(); }, first: "/data/clamd.sock", later: "/data/clamd-new.sock" },
  { name: "Proxies", route: "/proxies/", path: "/services/proxy/forward", field: (p) => p.getByPlaceholder("mgmt, lan"), prepare: async (p) => { await expect(p.getByText("Advanced options", { exact: true }).first().locator("xpath=ancestor::details[1]")).toHaveAttribute("open", ""); }, first: "lan, ", later: "lan, wan, " },
  { name: "VPN", route: "/vpn/", path: "/services/vpn", field: (p) => p.getByRole("textbox", { name: /^Peers \(JSON\)/ }), prepare: async (p) => { await p.getByText("Advanced peer settings", { exact: true }).click(); }, first: "[] ", later: "[ " },
];

for (const item of textPages) {
  test(`${item.name} keeps edits through subscription and its staged save, including later typing`, async ({ page }) => {
    const server = await mockAPI(page);
    await open(page, item.route, item.path);
    await item.prepare?.(page);
    const field = item.field(page);
    await expect(field).toBeVisible();
    await field.fill(item.first);
    server.change(item.path, item.name === "VPN"
      ? { wireguard: { enabled: true, interface: "wg0", peers: [] }, openvpn: { enabled: false } }
      : { ...(server.data[item.path] as object), enabled: true });
    await announce(page, item.path);
    await expect(page.getByRole("status", { name: "Unsaved edits" }).first()).toContainText("changed on the server");
    await expect(field).toHaveValue(item.first);
    const save = page.getByRole("button", { name: "Save", exact: true }).first();
    await reviewConflict(page, server, save);
    await expect(field).toHaveValue(item.first);
    // Hold the save echo, not just a synthetic event: the request helper will
    // dispatch CONFIG_STAGED and cause a real subscription read on release.
    let release!: () => void;
    server.hold = new Promise<void>((resolve) => { release = resolve; });
    await save.click();
    await expect.poll(() => server.writes.length).toBe(2);
    await field.fill(item.later);
    const refreshed = page.waitForResponse(read(item.path));
    release();
    await refreshed;
    await expect(field).toHaveValue(item.later);
    expect(server.attempts[1]).toMatchObject({ revision: revision(2), status: 200 });
    expect(server.writes[1].path).toBe(item.path);
    if (item.name === "DNS") expect(server.writes[1].body).toMatchObject({ upstreamServers: ["192.0.2.53", "192.0.2.54"] });
    if (item.name === "NTP") expect(server.writes[1].body).toMatchObject({ servers: ["pool.ntp.org", "ntp.lab"] });
    if (item.name === "Proxies") expect(server.writes[1].body).toMatchObject({ listenZones: ["lan"] });
    if (item.name === "VPN") expect(server.writes[1].body).toMatchObject({ wireguard: { peers: [] } });
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
  const dialog = page.getByRole("dialog");
  await dialog.getByRole("button", { name: "Edit JSON", exact: true }).click();
  const field = dialog.getByRole("textbox", { name: "Rule JSON", exact: true });
  await field.fill('{"id":"test-rule", "title":');
  await expect(dialog.getByRole("button", { name: "Save rule", exact: true })).toBeDisabled();
  server.change("/ids/rules", { enabled: true, rules: [] });
  await announce(page, "/ids/rules");
  await expect(field).toHaveValue('{"id":"test-rule", "title":');
  await expect(page.getByRole("status", { name: "Unsaved edits" })).toContainText("changed on the server");
  // The save submitted before the modal opened cannot acknowledge its draft.
  const refreshed = page.waitForResponse(read("/ids/rules"));
  release();
  await refreshed;
  await expect(dialog.getByRole("status").filter({ hasText: "IDS rules staged — commit to apply." })).toBeVisible();
  await expect(dialog.getByText("Edits made after that submission are not included.", { exact: true })).toBeVisible();
  expect(server.writes).toHaveLength(1);
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
    server.change(item.path, item.name === "Identities" ? { mappings: [] } : []);
    await announce(page, item.path);
    await expect(field).toHaveValue("unfinished, ");
    await expect(rowField).toHaveValue("row draft, ");
    await expect(page.getByRole("status", { name: "Unsaved edits" })).toContainText("changed on the server");
    // Reintroduce the row, then save it while the independent creation form
    // is unfinished. Its staged refresh must not reset that creation form.
    server.change(item.path, item.name === "Identities"
      ? { mappings: [{ ip: item.row, identities: ["operator"] }] } : [{ name: item.row }]);
    await announce(page, item.path, CONFIG_STAGED);
    await rowField.fill(item.name === "Identities" ? "supervisor" : "Saved row");
    await reviewConflict(page, server, row.getByRole("button", { name: "Save", exact: true }));
    if (item.name !== "Identities") await row.getByRole("button", { name: "Edit", exact: true }).click();
    await expect(rowField).toHaveValue(item.name === "Identities" ? "supervisor" : "Saved row");
    await Promise.all([
      page.waitForResponse(read(item.path)),
      row.getByRole("button", { name: "Save", exact: true }).click(),
    ]);
    await expect.poll(() => server.writes.length).toBe(2);
    expect(server.attempts[1]).toMatchObject({ revision: revision(3), status: 200 });
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
  server.change("/routing", { gateways: [{ name: "other", address: "192.0.2.1" }], routes: [], rules: [] });
  await announce(page, "/routing");
  await expect(field).toHaveValue("gateway draft");
  await expect(page.getByRole("status", { name: "Unsaved edits" })).toContainText("changed on the server");
  await page.getByText("Add static route (advanced)", { exact: true }).click();
  await page.getByPlaceholder("dst (CIDR or default)").fill("198.51.100.0/24");
  await reviewConflict(page, server, page.getByRole("button", { name: "Add route", exact: true }));
  await page.getByRole("button", { name: "Add route", exact: true }).click();
  await expect.poll(() => server.writes.length).toBe(2);
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
  server.change("/firewall/nat", { enabled: true });
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
  server.change("/firewall/nat", { enabled: false, egressZone: "wan", portForwards: [] });
  await announce(page, "/firewall/nat");
  await expect(field).toHaveValue("192.0.");
  await expect(page.getByRole("button", { name: "On", exact: true })).toBeVisible();
  await reviewConflict(page, server, page.getByRole("button", { name: "Save NAT", exact: true }));
  await page.getByRole("button", { name: "Save NAT", exact: true }).click();
  await expect.poll(() => server.writes.length).toBe(2);
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
  server.change("/services/dns", { enabled: true, upstreamServers: ["192.0.2.54"] });
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
  server.change("/zones", [{ name: "lan" }]);
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
  server.change("/services/proxy/reverse", { enabled: true, sites: [] });
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
  server.change("/ids/rules", { enabled: true, rules: [] });
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
  server.change("/zones", [{ name: "wan" }]);
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

const draftRule = { id: "ot-rule", description: "Original", action: "ALLOW", ics: { protocol: "modbus", functionCode: [3], mode: "monitor" } };

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
    server.change("/firewall/rules", []);
    for (const event of [CONFIG_STAGED, CONFIG_COMMITTED]) {
      await announce(page, "/firewall/rules", event);
      await expect(input).toHaveValue(raw);
      await expect(page.getByRole("status", { name: "Unsaved edits" }).first()).toBeVisible();
    }
    // Restore the row before retrying its update; revision consent does not
    // resurrect a rule that no longer exists on the server.
    server.change("/firewall/rules", [draftRule]);
    await announce(page, "/firewall/rules");
    const save = page.getByRole("button", { name: surface === "Firewall" ? "Save changes" : "Save filter", exact: true });
    await reviewConflict(page, server, save);
    let release!: () => void;
    server.hold = new Promise<void>((resolve) => { release = resolve; });
    await save.click();
    await expect.poll(() => server.writes.length).toBe(2);
    await input.fill(raw + (surface === "Firewall" ? "198.51." : "16,"));
    const refreshed = page.waitForResponse(read("/firewall/rules"));
    release();
    await refreshed;
    await expect(input).toHaveValue(raw + (surface === "Firewall" ? "198.51." : "16,"));
    expect(server.writes[1].body).toMatchObject(surface === "Firewall" ? { sources: ["192.0.2.0/24"] } : { ics: { functionCode: [3] } });
    await page.getByRole("button", { name: "Refresh", exact: true }).press("Enter");
    await expect(input).toHaveCount(surface === "Firewall" ? 1 : 0);
    if (surface === "Firewall") await expect(input).toHaveValue("");
  });
}

test("Firewall creation keeps failed submissions and later typing, independently of collection refreshes", async ({ page }) => {
  const server = await mockAPI(page);
  await open(page, "/firewall/", "/firewall/rules");
  const disclosure = page.getByRole("button", { name: "Create rule", exact: true })
    .and(page.locator('[aria-controls="create-rule-panel"]'));
  await expect(disclosure).toHaveAttribute("aria-expanded", "false");
  await disclosure.click();
  await expect(disclosure).toHaveAttribute("aria-expanded", "true");
  const form = page.locator("#create-rule-panel");
  const submit = form.getByRole("button", { name: "Create rule", exact: true });
  const id = form.getByPlaceholder("id (e.g. mb-allow)");
  const sources = form.getByPlaceholder("sources CIDR (csv)");
  await id.fill("new-rule");
  await sources.fill("192.0.2.0/24, ");
  await form.getByRole("button", { name: "Add source zone", exact: true }).click();
  const sourceZone = form.getByRole("combobox", { name: "Source zone 1", exact: true });
  await sourceZone.selectOption("lan");
  server.change("/zones", [{ name: "wan" }]);
  server.change("/firewall/rules", [draftRule]);
  await announce(page, "/firewall/rules");
  await expect(page.getByRole("row").filter({ hasText: "ot-rule" })).toBeVisible();
  await expect(sources).toHaveValue("192.0.2.0/24, ");
  await expect(sourceZone).toHaveValue("lan");
  await expect(sourceZone.getByRole("option", { selected: true })).toContainText("no longer on server");
  await reviewConflict(page, server, submit);
  server.failedWrites.add("/firewall/rules");
  await submit.click();
  await expect(page.getByText("rejected", { exact: true })).toBeVisible();
  await expect(id).toHaveValue("new-rule");
  await expect(sources).toHaveValue("192.0.2.0/24, ");
  server.failedWrites.clear();
  let release!: () => void;
  server.hold = new Promise<void>((resolve) => { release = resolve; });
  await submit.click();
  await expect.poll(() => server.writes.length).toBe(3);
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
  server.change("/dataplane", { ...server.data["/dataplane"] as object, dpiMode: "enforce" });
  await announce(page, "/dataplane");
  await expect(parsing).toHaveValue("strict");
  await expect(page.getByRole("status", { name: "Unsaved edits" })).toBeVisible();
  await reviewConflict(page, server, page.getByRole("button", { name: "Save", exact: true }));
  await expect(parsing).toHaveValue("strict");
  server.failedWrites.add("/dataplane");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByText("Not saved: rejected")).toBeVisible();
  await expect(parsing).toHaveValue("strict");
  server.failedWrites.clear();
  let release!: () => void;
  server.hold = new Promise<void>((resolve) => { release = resolve; });
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => server.writes.length).toBe(3);
  await parsing.selectOption("tolerant");
  release();
  await expect(page.getByRole("button", { name: "Save", exact: true })).toBeEnabled();
  await expect(parsing).toHaveValue("tolerant");
  expect(server.writes[2].body).toMatchObject({ dpiMode: "enforce", dpiIcsParsing: { modbus: "strict" } });
  expect(server.attempts.map(attempt => attempt.status)).toEqual([412, 400, 200]);
  expect(server.attempts.map(attempt => attempt.revision)).toEqual([revision(1), revision(2), revision(2)]);
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  await page.getByRole("button", { name: "Add Exclusion", exact: true }).click();
  const reason = page.getByPlaceholder("Reason (optional)");
  await reason.fill("unfinished, ");
  server.change("/dataplane", { ...server.data["/dataplane"] as object, dpiMode: "monitor" });
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
  server.change("/zones", [{ name: "wan" }, { name: "dmz" }]);
  server.change("/templates/ics", [{ name: "Test baseline", description: "Changed template", protocol: "modbus", parameters: [] }]);
  for (const event of [CONFIG_STAGED, CONFIG_COMMITTED]) {
    await announce(page, "/zones", event);
    await expect(codes).toHaveValue("3, ");
    await expect(page.getByRole("status", { name: "Unsaved edits" })).toBeVisible();
  }
  await expect(page.getByRole("button", { name: "lan (no longer on server)", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Preview", exact: true }).click();
  await expect(page.getByText("Preview: 0 Rule(s)")).toBeVisible();
  await expect(codes).toHaveValue("3, ");
  await reviewConflict(page, server, page.getByRole("button", { name: "Stage", exact: true }));
  server.failedWrites.add("/templates/ics/apply");
  await page.getByRole("button", { name: "Stage", exact: true }).click();
  await expect(page.getByText("rejected", { exact: true })).toBeVisible();
  await expect(codes).toHaveValue("3, ");
  server.failedWrites.clear();
  let release!: () => void;
  server.hold = new Promise<void>((resolve) => { release = resolve; });
  await page.getByRole("button", { name: "Stage", exact: true }).click();
  await expect.poll(() => server.writes.length).toBe(4);
  await codes.fill("3, 16, ");
  release();
  await expect(page.getByRole("button", { name: "Stage", exact: true })).toBeEnabled();
  await expect(codes).toHaveValue("3, 16, ");
  expect(server.writes[3].body).toMatchObject({ parameters: { codes: "3, " }, sourceZones: ["lan"] });
  await page.getByRole("button", { name: "Refresh", exact: true }).press("Enter");
  await expect(codes).toHaveCount(0);
});


for (const surface of ["Firewall", "ICS"]) {
  test(`${surface} pristine modal adopts the new server copy without an unsaved warning`, async ({ page }) => {
    const server = await mockAPI(page);
    server.data["/firewall/rules"] = [draftRule];
    await open(page, surface === "Firewall" ? "/firewall/" : "/ics/", "/firewall/rules");
    await page.getByRole("row").filter({ hasText: "ot-rule" }).getByRole("button", { name: "Edit", exact: true }).click();
    server.change("/firewall/rules", [{ ...draftRule, description: "New server copy", ics: { ...draftRule.ics, functionCode: [16] } }]);
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
  server.change("/dataplane", { ...server.data["/dataplane"] as object, dpiMode: "enforce" });
  await announce(page, "/dataplane");
  await expect(modal.getByRole("status", { name: "Unsaved edits" })).toBeVisible();
  await reviewConflict(page, server, modal.getByRole("button", { name: "Save", exact: true }), modal);
  let release!: () => void;
  server.hold = new Promise<void>((resolve) => { release = resolve; });
  await modal.getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => server.writes.length).toBe(2);
  await modal.getByRole("button", { name: "Enable All", exact: true }).click();
  release();
  await expect(modal.getByRole("button", { name: "Save", exact: true })).toBeEnabled();
  expect(server.writes[1].body).toMatchObject({ dpiProtocols: { http: false }, dpiMode: "enforce" });
  await modal.getByRole("button", { name: "Save", exact: true }).click();
  await expect(modal).toHaveCount(0);
  expect(server.writes[2].body).toMatchObject({ dpiProtocols: { http: true } });
  expect(server.attempts.map(attempt => attempt.status)).toEqual([412, 200, 200]);
  expect(server.attempts.map(attempt => attempt.revision)).toEqual([revision(1), revision(2), revision(3)]);
});

test("DPI conflict Reload discards parsing edits before a fresh reviewed save", async ({ page }) => {
  const server = await mockAPI(page);
  await open(page, "/firewall/", "/dataplane");
  await page.getByRole("button", { name: "Configure", exact: true }).first().click();
  const parsing = page.getByRole("combobox", { name: "Modbus/TCP parsing" });
  await parsing.selectOption("strict");
  server.change("/dataplane", { ...server.data["/dataplane"] as object, dpiMode: "enforce", dpiIcsParsing: { modbus: "tolerant" } });
  await announce(page, "/dataplane");
  const rejected = page.waitForResponse(r => r.status() === 412 && r.request().method() === "POST");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await rejected;
  await expect(page.getByText("Configuration changed since you loaded it", { exact: true })).toBeVisible();
  await expect(parsing).toHaveValue("strict");
  await Promise.all([
    page.waitForResponse(read("/dataplane")),
    page.getByRole("button", { name: "Reload", exact: true }).click(),
  ]);
  await expect(parsing).toHaveCount(0);
  expect(server.writes).toHaveLength(1);
  await page.getByRole("button", { name: "Configure", exact: true }).first().click();
  await expect(parsing).toHaveValue("tolerant");
  await parsing.selectOption("strict");
  const saved = page.waitForResponse(r => r.request().method() === "POST" && new URL(r.url()).pathname === prefix + "/dataplane");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  expect((await saved).status()).toBe(200);
  expect(server.attempts.map(attempt => attempt.revision)).toEqual([revision(1), revision(2)]);
  expect(server.counter).toBe(3);
});

for (const item of [
  { name: "Zones", route: "/zones/", path: "/zones", placeholder: "name (e.g. ot)" },
  { name: "Interfaces", route: "/interfaces/", path: "/interfaces", placeholder: "name (e.g. tunnel1)" },
  { name: "Identities", route: "/identities/", path: "/identities", placeholder: "identities (comma-separated)" },
]) {
  test(`${item.name} retains disabled drafts through a failed explicit refresh`, async ({ page }) => {
    const server = await mockAPI(page);
    await open(page, item.route, item.path);
    const field = page.getByPlaceholder(item.placeholder);
    await field.fill("unfinished");
    server.failedReads.add(item.path);
    await Promise.all([page.waitForResponse(read(item.path)), page.getByRole("button", { name: "Refresh", exact: true }).click()]);
    await expect(field).toBeDisabled();
    await expect(field).toHaveValue("unfinished");
    expect(server.writes).toEqual([]);
    server.failedReads.clear();
    await announce(page, item.path);
    await expect(field).toBeEnabled();
    await expect(field).toHaveValue("unfinished");
  });
}

test("Routing keeps its authoritative subtree and an unfinished gateway across failed refresh and recovery", async ({ page }) => {
  const server = await mockAPI(page);
  const original = { gateways: [], routes: [{ dst: "198.51.100.0/24", iface: "eth0", metric: 42 }], rules: [{ table: 100, src: "192.0.2.0/24" }] };
  server.data["/routing"] = original;
  await open(page, "/routing/", "/routing");
  await page.getByText("Add gateway (advanced)", { exact: true }).click();
  const name = page.getByPlaceholder("isp1");
  await name.fill("new-gateway");
  await page.getByPlaceholder("192.168.240.1").fill("192.0.2.1");
  server.failedReads.add("/routing");
  await Promise.all([page.waitForResponse(read("/routing")), page.getByRole("button", { name: "Refresh", exact: true }).click()]);
  await expect(name).toBeDisabled();
  await expect(name).toHaveValue("new-gateway");
  expect(server.writes).toEqual([]);
  server.failedReads.clear();
  await announce(page, "/routing");
  await expect(name).toBeEnabled();
  await page.getByRole("button", { name: "Add", exact: true }).click();
  await expect.poll(() => server.writes.length).toBe(1);
  expect(server.writes[0]).toEqual({ path: "/routing", body: { ...original, gateways: [{ name: "new-gateway", address: "192.0.2.1" }] } });
});

for (const surface of ["Firewall", "ICS"]) {
  test(`${surface} modal cannot save a retained draft after a failed refresh`, async ({ page }) => {
    const server = await mockAPI(page);
    server.data["/firewall/rules"] = [draftRule];
    await open(page, surface === "Firewall" ? "/firewall/" : "/ics/", "/firewall/rules");
    await page.getByRole("row").filter({ hasText: "ot-rule" }).getByRole("button", { name: "Edit", exact: true }).click();
    const input = surface === "Firewall" ? page.getByPlaceholder("sources CIDR (csv)").last() : page.getByPlaceholder("3, 16");
    const value = surface === "Firewall" ? "192.0.2.0/24, " : "3, ";
    await input.fill(value);
    server.failedReads.add("/firewall/rules");
    await announce(page, "/firewall/rules");
    const save = page.getByRole("button", { name: surface === "Firewall" ? "Save changes" : "Save filter", exact: true });
    await expect(save).toBeDisabled();
    await expect(input).toHaveValue(value);
    expect(server.writes).toEqual([]);
    server.failedReads.clear();
    await announce(page, "/firewall/rules");
    await expect(save).toBeEnabled();
    await expect(input).toHaveValue(value);
  });
}

test("Config JSON keeps its draft through a failed Refresh and stages the complete recovered document", async ({ page }) => {
  const server = await mockAPI(page);
  const original = { schema_version: "0.1.9", system: { hostname: "existing" }, services: { syslog: { forwarders: [{ address: "192.0.2.1", port: 514 }] } } };
  server.data["/config/diff"] = { running: original, candidate: original, changed: false, changedSections: [] };
  await open(page, "/config/?tab=candidate", "/config/diff");
  const field = page.getByRole("textbox", { name: "Staged config JSON", exact: true });
  const next = { ...original, system: { hostname: "edited" } };
  await field.fill(JSON.stringify(next));
  server.failedReads.add("/config/diff");
  await Promise.all([page.waitForResponse(read("/config/diff")), page.getByRole("button", { name: "Refresh", exact: true }).click()]);
  const save = page.getByRole("button", { name: "Save staged config", exact: true });
  await expect(save).toBeDisabled();
  await expect(field).toHaveValue(JSON.stringify(next));
  expect(server.writes).toEqual([]);
  server.failedReads.clear();
  await announce(page, "/config/diff");
  await expect(save).toBeEnabled();
  await expect(field).toHaveValue(JSON.stringify(next));
  await save.click();
  await expect.poll(() => server.writes.length).toBe(1);
  expect(server.writes[0]).toEqual({ path: "/config/candidate", body: next });
});

test("Wizard cannot stage NAT after a failed refresh and retains its publish draft on recovery", async ({ page }) => {
  const server = await mockAPI(page);
  const original = { enabled: true, egressZone: "wan", portForwards: [{ id: "existing", listenPort: 8080, destIp: "192.0.2.4", destPort: 80 }] };
  server.data["/firewall/nat"] = original;
  await open(page, "/wizard/", "/firewall/nat");
  await page.getByRole("button", { name: /Publish Internal Service/ }).click();
  await page.getByPlaceholder("e.g. 192.168.1.10").fill("192.0.2.5");
  await page.getByPlaceholder("e.g. 443").fill("443");
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await page.getByRole("button", { name: "Next", exact: true }).click();
  await page.getByRole("combobox").selectOption("wan");
  await page.getByRole("button", { name: "Next", exact: true }).click();
  server.failedReads.add("/firewall/nat");
  await announce(page, "/firewall/nat");
  const stage = page.getByRole("button", { name: "Stage", exact: true });
  await expect(stage).toBeDisabled();
  expect(server.writes).toEqual([]);
  server.failedReads.clear();
  await announce(page, "/firewall/nat");
  await expect(stage).toBeEnabled();
  await stage.click();
  await expect.poll(() => server.writes.length).toBe(1);
  const written = server.writes.find((write) => write.path === "/firewall/port-forwards")!;
  expect(written.body).toEqual({ allowRule: true, forward: {
    id: expect.any(String), enabled: true, description: "Port forward TCP/443 to 192.0.2.5 (wizard)",
    proto: "tcp", listenPort: 443, destIp: "192.0.2.5", destPort: 443, ingressZone: "wan",
  } });
  expect(server.data["/firewall/nat"]).toMatchObject({ ...original, portForwards: [original.portForwards[0], expect.objectContaining({ destIp: "192.0.2.5" })] });
});

test("a confirmation opened before a failed refresh cannot stage its stale callback", async ({ page }) => {
  const server = await mockAPI(page);
  await open(page, "/zones/", "/zones");
  const row = page.getByRole("row").filter({ has: page.getByRole("cell", { name: "wan", exact: true }) });
  await row.getByRole("button", { name: "Delete", exact: true }).click();
  server.failedReads.add("/zones");
  await announce(page, "/zones");
  await expect(page.getByRole("alert").filter({ hasText: "Configuration unavailable" })).toBeVisible();
  await page.getByRole("dialog").getByRole("button", { name: "Delete", exact: true }).click();
  expect(server.writes).toEqual([]);
});
