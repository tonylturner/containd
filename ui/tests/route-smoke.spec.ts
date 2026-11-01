import { expect, test } from "./fixtures/topology-test";
import { routes } from "./fixtures/routes";
import { snapshot } from "./fixtures/iec104-inventory";
import { pressure } from "./fixtures/iec104-pressure";
import { mockProtection } from "./fixtures/protection-api";
import { interfaceAddresses, OS_ADDRESS_HINT, runtimeFor } from "../lib/interface-addresses";
import type { Interface, SystemInspection } from "../lib/api";

const routeExpectations = {
  "/": { heading: "Dashboard", api: "/dashboard" },
  "/alerts": { heading: "IDS Alerts", api: "/events" },
  "/assets": { heading: "Assets", api: "/assets" },
  "/audit": { heading: "Audit Log", api: "/audit" },
  "/config": { heading: "Config", api: "/config/diff" },
  "/dataplane": { heading: "PCAP", api: "/pcap/config" },
  "/dhcp": { heading: "DHCP", api: "/services/dhcp" },
  "/diagnostics": { heading: "Diagnostics", api: "/interfaces/state" },
  "/events": { heading: "Events", api: "/events" },
  "/firewall": { heading: "Firewall Rules", api: "/firewall/rules" },
  "/flows": { heading: "Active Flows", api: "/flows" },
  // This is a static denial page, with no page-specific data request.
  "/forbidden": { heading: "Access denied", api: null },
  "/ics": { heading: "ICS / OT Protocol Filters", api: "/firewall/rules" },
  "/identities": { heading: "Identity Bindings", api: "/identities" },
  "/ids": { heading: "IDS Rules", api: "/ids/rules" },
  "/interfaces": { heading: "Interfaces", api: "/interfaces" },
  "/login": { heading: "containd login", api: "/auth/me" },
  "/monitoring": { heading: "Monitoring Overview", api: "/flows" },
  "/nat": { heading: "NAT", api: "/firewall/nat" },
  "/pcap": { heading: "PCAP Analysis", api: "/learn/datasets" },
  "/proxies": { heading: "Proxies", api: "/services/proxy/forward" },
  "/routing": { heading: "Routing", api: "/routing" },
  "/sessions": { heading: "Sessions", api: "/conntrack" },
  "/system/services": { heading: "Services", api: "/services/status" },
  "/system/services/av": { heading: "Antivirus / ICAP", api: "/services/av" },
  "/system/services/dns": { heading: "DNS", api: "/services/dns" },
  "/system/services/ntp": { heading: "NTP", api: "/services/ntp" },
  "/system/services/syslog": { heading: "Syslog", api: "/services/syslog" },
  "/system/settings": { heading: "System Settings", api: "/system/tls" },
  "/system/users": { heading: "User Management", api: "/users" },
  "/templates": { heading: "ICS Rule Templates", api: "/templates/ics" },
  "/topology": { heading: "Topology", api: "/config" },
  "/vpn": { heading: "VPN", api: "/services/vpn" },
  "/wizard": { heading: "Policy Wizard", api: "/zones" },
  "/zones": { heading: "Zones", api: "/zones" },
} satisfies Record<(typeof routes)[number], { heading: string; api: string | null }>;

const adminUser = {
  id: "admin-1",
  username: "containd",
  role: "admin",
  firstName: "Admin",
  lastName: "User",
  mfaEnabled: false,
  mfaRequired: false,
};

const zones = [
  { name: "wan", alias: "WAN" },
  { name: "ot", alias: "OT" },
  { name: "lan", alias: "LAN" },
];

const interfaces: Interface[] = [
  {
    name: "wan",
    device: "eth1",
    zone: "wan",
    addresses: ["192.0.2.1/24"],
    access: { mgmt: true, http: true, https: true, ssh: true },
  },
  {
    name: "ot1",
    device: "eth2",
    zone: "ot",
    addressMode: "dhcp",
  },
  {
    name: "lan1",
    device: "eth0",
    zone: "lan",
    access: { mgmt: true, http: true, https: true, ssh: true },
  },
];

const interfaceState = [
  {
    name: "eth1",
    index: 2,
    up: true,
    mtu: 1500,
    mac: "02:00:00:00:00:01",
    addrs: ["192.168.240.2/24"],
  },
  {
    name: "eth0",
    index: 1,
    up: true,
    mtu: 1500,
    mac: "02:00:00:00:00:02",
    addrs: ["fe80::1/64", "fea0::1/64", "2001:db8::1/64", "192.168.242.2/24"],
  },
  {
    name: "eth2",
    index: 3,
    up: true,
    mtu: 1500,
    mac: "02:00:00:00:00:03",
    addrs: ["192.168.243.2/24"],
  },
  {
    // A logical name must not shadow an explicit device binding.
    name: "lan1",
    index: 4,
    up: true,
    mtu: 1500,
    mac: "02:00:00:00:00:04",
    addrs: ["198.51.100.99/24"],
  },
];

const rulesetPreview = {
  snapshot: {},
  ruleset: "table inet containd {\n}\n",
  runtime: { iec104EnvelopeOpen: false, reason: "IEC 104 envelope not used by this candidate" },
  warnings: [
    {
      ruleId: "tpl-modbus-deny-writes",
      shadowedBy: "tpl-modbus-allow-reads",
      action: "DENY",
      message: "shadowed by earlier ALLOW rule tpl-modbus-allow-reads, which matches all of its traffic",
    },
  ],
};

const malformedFirewallRules = [
  {
    id: "tpl-modbus-allow-reads",
    description: "Allow Modbus reads",
    sourceZones: "ot",
    destZones: { 0: "lan" },
    protocols: { name: "tcp", port: 502 },
    ics: {
      protocol: "modbus",
      functionCode: 3,
      addresses: "0-10",
      mode: "enforce",
      readOnly: true,
    },
    action: "ALLOW",
  },
  {
    id: "tpl-modbus-deny-writes",
    sourceZones: ["ot"],
    destZones: ["lan"],
    protocols: [{ name: "tcp", port: "502" }],
    ics: {
      protocol: "modbus",
      functionCode: { 0: 5, 1: 6, 2: 16 },
      mode: "enforce",
      writeOnly: true,
    },
    action: "DENY",
  },
];

const dashboard = {
  health: { status: "ok", component: "mgmt" },
  counts: {
    assets: 0,
    zones: zones.length,
    interfaces: interfaces.length,
    rules: malformedFirewallRules.length,
    icsRules: malformedFirewallRules.length,
  },
  eventStats: {
    total: 0,
    idsAlerts: 0,
    modbusWrites: 0,
    avDetections: 0,
    avBlocks: 0,
  },
  services: {},
  user: adminUser,
  lastActivity: null,
};

const systemStats = {
  cpu: { usagePercent: 18, numCPU: 8 },
  memory: {
    totalBytes: 8 * 1024 * 1024 * 1024,
    usedBytes: 3 * 1024 * 1024 * 1024,
    availableBytes: 5 * 1024 * 1024 * 1024,
    usagePercent: 37.5,
  },
  disk: {
    totalBytes: 256 * 1024 * 1024 * 1024,
    usedBytes: 96 * 1024 * 1024 * 1024,
    availableBytes: 160 * 1024 * 1024 * 1024,
    usagePercent: 37.5,
  },
  ruleEval: { rulesLoaded: malformedFirewallRules.length, avgLatencyMs: 0.9 },
  container: {
    running: true,
    id: "containd-test",
    image: "containd:test",
    uptime: "12m",
    memUsedBytes: 256 * 1024 * 1024,
    memLimitBytes: 1024 * 1024 * 1024,
    memPercent: 25,
  },
  runtime: {
    goroutines: 42,
    heapAllocMB: 64,
    heapSysMB: 128,
    gcPauseMsAvg: 1.5,
    uptime: "12m",
  },
  collectedAt: "2026-03-14T00:00:00Z",
};

const auditRecords = [
  {
    id: "audit-1",
    timestamp: "2026-03-14T00:00:00Z",
    actor: "containd",
    source: "ui",
    action: "templates.ics.apply",
    target: "modbus_read_only",
    result: "success",
  },
];

const systemInspection: SystemInspection = {
  host: { kernel: "6.12", os: "Linux", arch: "aarch64", hostUptime: "12h", numCPU: 8 },
  runtime: { dockerVersion: "28.0", containerdVersion: "2.0", cgroupDriver: "cgroupfs", storageDriver: "overlay2" },
  container: {
    id: "containd-test",
    image: "containd:test",
    restartPolicy: "unless-stopped",
    restartCount: 0,
    networkMode: "bridge",
    privileged: false,
    seccompProfile: "default",
    apparmorProfile: "",
    readonlyRootfs: true,
    noNewPrivileges: true,
    capabilities: [],
    mounts: [],
    envVars: [],
  },
  process: { pid: 1, goVersion: "go1.25.8", fdCount: 30, fdSoftLimit: 1024, fdHardLimit: 4096 },
  security: { dockerSocketMounted: false, cgroupCPUQuota: "800000 100000", cgroupPIDsLimit: "512" },
};

const defaultConfig = {
  system: { hostname: "containd" },
  interfaces,
  zones,
  assets: [],
  objects: [],
  routing: { gateways: [], routes: [], rules: [] },
  dataplane: {
    captureInterfaces: ["wan"],
    dpiEnabled: true,
    dpiMode: "monitor",
    dpiProtocols: {},
    dpiIcsProtocols: {},
  },
  firewall: {
    rules: malformedFirewallRules,
    nat: { enabled: false, sourceZones: [], portForwards: [] },
  },
  ids: { enabled: false, rules: [] },
  services: {},
};

function json(body: unknown, status = 200) {
  return {
    status,
    contentType: "application/json",
    headers: { "X-Containd-Revision": "0123456789abcdef.1" },
    body: JSON.stringify(body),
  };
}

function responseFor(pathname: string) {
  if (pathname === "/api/v1/auth/me" || pathname === "/api/v1/auth/session") {
    return json(adminUser);
  }
  if (pathname === "/api/v1/inventory/iec104") return json(snapshot);
  if (pathname === "/api/v1/diagnostics/iec104") return json(pressure);
  if (pathname === "/api/v1/dashboard") return json(dashboard);
  if (pathname === "/api/v1/learn/datasets" || pathname === "/api/v1/learn/watches") {
    return json({ items: [], nextCursor: "" });
  }
  if (pathname === "/api/v1/learn/counters") {
    return json({ records: 0, bytes: 0, evictedRecords: 0, evictedBytes: 0, expiredRecords: 0, lostBatches: 0, rejectedParents: 0, withheld: {} });
  }
  if (pathname === "/api/v1/evidence/status") {
    return json({ audit: { state: "ok", failures: 0 }, forwarding: [] });
  }
  if (pathname === "/api/v1/zones") return json(zones);
  if (pathname === "/api/v1/interfaces") return json(interfaces);
  if (pathname === "/api/v1/interfaces/state") return json(interfaceState);
  if (
    pathname === "/api/v1/firewall/rules" ||
    pathname === "/api/v1/firewall/ics-rules"
  ) {
    return json(malformedFirewallRules);
  }
  if (pathname === "/api/v1/firewall/counters") {
    return json({
      snapshotVersion: "v1",
      since: "2026-03-14T00:00:00Z",
      rules: malformedFirewallRules.map((r) => ({ ruleId: r.id, action: r.action, packets: 10, bytes: 600 })),
    });
  }
  if (pathname === "/api/v1/firewall/shadow-counters") {
    return json({ available: true, unit: "messages", rules: [] });
  }
  if (pathname === "/api/v1/audit") return json(auditRecords);
  if (pathname === "/api/v1/firewall/nat") {
    return json({ enabled: false, sourceZones: [], portForwards: [] });
  }
  if (pathname === "/api/v1/config" || pathname === "/api/v1/config/candidate") {
    return json(defaultConfig);
  }
  if (pathname === "/api/v1/config/diff") {
    return json({ changed: false, changedSections: [], pendingConfirm: null, running: defaultConfig, candidate: defaultConfig, idsBank: { running: { count: 0, sha256: "empty" }, candidate: { count: 0, sha256: "empty" } } });
  }
  if (pathname === "/api/v1/config/backups") return json([]);
  if (pathname === "/api/v1/routing") {
    return json({ gateways: [], routes: [], rules: [] });
  }
  if (pathname === "/api/v1/routing/os") {
    return json({ routes: [] });
  }
  if (pathname === "/api/v1/dataplane") {
    return json({
      captureInterfaces: ["wan"],
      dpiEnabled: true,
      dpiMode: "monitor",
      dpiProtocols: {},
      dpiIcsProtocols: {},
    });
  }
  if (pathname === "/api/v1/dataplane/ruleset") {
    return json(rulesetPreview);
  }
  if (pathname === "/api/v1/dataplane/ics-coverage") {
    return json({ candidate: [], applied: [], appliedAt: "2026-10-26T06:00:00Z" });
  }
  if (pathname === "/api/v1/system/management-reservation") {
    return json({ active: false, guard: { active: false, faults: 0 } });
  }
  if (pathname === "/api/v1/dataplane/ruleset/status") {
    return json({ installed: true, appliedAt: "2026-10-26T06:00:00Z", snapshotVersion: "v1" });
  }
  if (
    pathname === "/api/v1/assets" ||
    pathname === "/api/v1/objects" ||
    pathname === "/api/v1/events" ||
    pathname === "/api/v1/flows" ||
    pathname === "/api/v1/anomalies" ||
    pathname === "/api/v1/conntrack" ||
    pathname === "/api/v1/inventory" ||
    pathname === "/api/v1/signatures" ||
    pathname === "/api/v1/signatures/matches" ||
    pathname === "/api/v1/templates" ||
    pathname === "/api/v1/templates/ics" ||
    pathname === "/api/v1/users" ||
    pathname === "/api/v1/ids/sources" ||
    pathname === "/api/v1/pcap/list"
  ) {
    return json([]);
  }
  if (pathname === "/api/v1/dhcp/leases") return json({ leases: [] });
  if (pathname === "/api/v1/identities") return json({ mappings: [] });
  if (pathname === "/api/v1/security/conduits") return json([]);
  if (pathname === "/api/v1/services/status") return json({ faults: [], av: { available: false, error: "engine unavailable" } });
  if (
    pathname === "/api/v1/services/syslog" ||
    pathname === "/api/v1/services/dns" ||
    pathname === "/api/v1/services/ntp" ||
    pathname === "/api/v1/services/dhcp" ||
    pathname === "/api/v1/services/vpn" ||
    pathname === "/api/v1/services/av" ||
    pathname === "/api/v1/services/proxy/forward" ||
    pathname === "/api/v1/services/proxy/reverse"
  ) {
    return json({});
  }
  if (pathname === "/api/v1/services/vpn/openvpn/clients") {
    return json({ clients: [] });
  }
  if (pathname === "/api/v1/services/av/defs") {
    return json({ path: "/data/av", files: [], definitions: [] });
  }
  if (pathname === "/api/v1/services/vpn/wireguard/status") {
    return json({ interface: "wg0", peers: [] });
  }
  if (pathname === "/api/v1/pcap/config") {
    return json({ interfaces: [], mode: "once" });
  }
  if (pathname === "/api/v1/pcap/status") {
    return json({ running: false, interfaces: [] });
  }
  if (pathname === "/api/v1/simulation") return json({ running: false });
  if (
    pathname === "/api/v1/stats/protocols" ||
    pathname === "/api/v1/stats/top-talkers"
  ) {
    return json([]);
  }
  if (pathname === "/api/v1/ids/rules") {
    return json({ enabled: false, rules: [] });
  }
  if (pathname === "/api/v1/system/stats") {
    return json(systemStats);
  }
  if (pathname === "/api/v1/system/inspection") return json(systemInspection);
  if (pathname === "/api/v1/system/tls") {
    return json({});
  }
  if (pathname === "/api/v1/health") {
    return json({ status: "ok", component: "mgmt" });
  }
  throw new Error(`Unmocked GET API path: ${pathname}`);
}

test.beforeEach(async ({ page }) => {
  await page.route("**/api/v1/**", async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === "/api/v1/events" && url.searchParams.has("query")) {
      await route.fulfill(json({ events: [], historyTruncated: false }));
      return;
    }
    if (route.request().method() === "GET") {
      await route.fulfill(responseFor(url.pathname));
      return;
    }
    if (route.request().method() === "PATCH" && url.pathname === "/api/v1/interfaces/external-test") {
      await route.fulfill(json({ name: "external-test", ...route.request().postDataJSON() }));
      return;
    }
    throw new Error(`Unmocked API request: ${route.request().method()} ${url.pathname}`);
  });
  await mockProtection(page);
});

for (const path of routes) {
  test(`route smoke ${path}`, async ({ page }) => {
    // Match the authenticated fixture before mount-time admin data loaders run.
    await page.addInitScript(() => localStorage.setItem("containd.auth.role", "admin"));
    const consoleErrors: string[] = [];
    const pageErrors: string[] = [];

    page.on("console", (msg) => {
      if (msg.type() === "error") consoleErrors.push(msg.text());
    });
    page.on("pageerror", (err) => {
      pageErrors.push(String(err));
    });

    const { heading, api } = routeExpectations[path];
    const loaded = api ? page.waitForResponse((res) =>
      res.request().method() === "GET" && new URL(res.url()).pathname === `/api/v1${api}`,
    ) : null;
    await page.goto(path);
    if (loaded) expect((await loaded).status()).toBe(200);
    await expect(page).toHaveURL(new RegExp(`${path === "/" ? "/" : path}/?$`));
    await expect(page.getByRole("heading", { name: heading, exact: true, level: 1 })).toBeVisible();
    await page.waitForLoadState("networkidle");

    expect(pageErrors).toEqual([]);
    expect(consoleErrors).toEqual([]);
  });
}

test("firewall ruleset preview lists rules that do not act as written", async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem("containd.auth.role", "admin"));
  await page.goto("/firewall");
  const button = page.getByRole("button", { name: "Preview", exact: true });
  await expect(button).toBeVisible();
  const response = page.waitForResponse((res) => new URL(res.url()).pathname === "/api/v1/dataplane/ruleset");
  await button.click();
  await response;
  const warning = page.getByRole("status").filter({ hasText: "Rules that do not act as written" });
  await expect(warning).toContainText("shadowed");
  await expect(warning).toContainText("tpl-modbus-deny-writes: shadowed by earlier ALLOW rule tpl-modbus-allow-reads");
});

test("templates describe maintenance windows as scheduled allows", async ({ page }) => {
  await page.goto("/templates");
  await expect(page.getByText("Maintenance window rules are scheduled ALLOW rules")).toBeVisible();
  await expect(page.getByText("inactive", { exact: false })).toHaveCount(0);
});

test("dashboard health keeps twelve pixels between uptime and gauges", async ({ page }) => {
  await page.goto("/");
  const uptime = page.getByText("Uptime: 12m", { exact: true }).locator("..");
  const cpu = page.getByText("CPU", { exact: true }).locator("..");
  await expect(uptime).toBeVisible();
  const uptimeBox = (await uptime.boundingBox())!;
  const cpuBox = (await cpu.boundingBox())!;
  expect(cpuBox.y - uptimeBox.y - uptimeBox.height).toBe(12);
});

test("interface addresses prefer config, then the bound device, without mutating either", () => {
  const before = JSON.stringify({ interfaces, interfaceState });
  expect(interfaceAddresses(interfaces[0], interfaceState)).toEqual({
    source: "config", addrs: ["192.0.2.1/24"],
  });
  const lan = interfaces.find((i) => i.name === "lan1")!;
  expect(runtimeFor(lan, interfaceState)?.name).toBe("eth0");
  expect(interfaceAddresses(lan, interfaceState)).toEqual({
    source: "os", addrs: ["192.168.242.2/24", "2001:db8::1/64"],
  });
  expect(interfaceAddresses({ name: "eth0" }, interfaceState).source).toBe("os");
  expect(interfaceAddresses({ name: "lan1", device: "missing" }, interfaceState)).toEqual({
    source: "none", addrs: [],
  });
  expect(interfaceAddresses({ name: "missing", addressMode: "dhcp" }, interfaceState)).toEqual({
    source: "dhcp", addrs: [],
  });
  expect(interfaceAddresses({ name: "eth0", addressMode: "dhcp", addresses: ["192.0.2.9/24"] }, interfaceState).source).toBe("dhcp");
  expect(interfaceAddresses({ name: "missing", addresses: ["2001:db8::2/64"] }, [])).toEqual({
    source: "config", addrs: ["2001:db8::2/64"],
  });
  expect(interfaceAddresses({ name: "eth0" }, [{
    ...interfaceState[0], name: "eth0", addrs: ["fe80::1/64", "fe90::1/64", "fea0::1/64", "febf::1/64"],
  }])).toEqual({ source: "os", addrs: [] });
  expect(JSON.stringify({ interfaces, interfaceState })).toBe(before);
});

test("Interfaces shows configured, external OS/Docker, and DHCP addresses", async ({ page }) => {
  const writes: string[] = [];
  page.on("request", (req) => {
    if (req.url().includes("/api/v1/") && req.method() !== "GET") writes.push(req.url());
  });
  await page.goto("/interfaces");
  const row = (name: string) => page.getByRole("row").filter({
    has: page.getByRole("cell", { name, exact: true }),
  });
  const configured = row("wan").getByRole("cell").nth(5);
  await expect(configured).toHaveText("192.0.2.1/24");
  await expect(configured.getByRole("img")).toHaveCount(0);
  const inspectWAN = row("wan").getByRole("button", { name: "Inspect", exact: true });
  await inspectWAN.click();
  await expect(inspectWAN).toHaveAttribute("aria-expanded", "true");
  const wanDetails = page.locator(`[id="${await inspectWAN.getAttribute("aria-controls")}"]`);
  await expect(wanDetails.getByText("Mode", { exact: true }).locator("..")).toHaveText(/^Mode\s*static$/);

  const fallback = row("lan1").getByRole("cell").nth(5);
  await expect(fallback).toHaveText("192.168.242.2/24, 2001:db8::1/64");
  await expect(fallback.getByRole("img", { name: "Detected address" })).toBeVisible();
  await expect(fallback.getByTitle(OS_ADDRESS_HINT)).toBeVisible();
  await expect(fallback.locator("[title]").first()).toHaveAttribute("title", interfaceState[1].addrs.join(", "));
  const inspectLAN = row("lan1").getByRole("button", { name: "Inspect", exact: true });
  await inspectLAN.click();
  await expect(inspectLAN).toHaveAttribute("aria-expanded", "true");
  const lanDetails = page.locator(`[id="${await inspectLAN.getAttribute("aria-controls")}"]`);
  await expect(lanDetails.getByText("Mode", { exact: true }).locator("..")).toHaveText(/^Mode\s*external$/);
  const dhcp = row("ot1").getByRole("cell").nth(5);
  await expect(dhcp).toHaveText("dhcp (192.168.243.2/24)");
  await expect(dhcp.getByRole("img")).toHaveCount(0);
  expect(writes).toEqual([]);
});

for (const stored of [
  {},
  { addressMode: "", addresses: [] },
  { addresses: ["192.0.2.2/24"] },
  { addressMode: "static", addresses: [] },
  { addressMode: "dhcp", addresses: [] },
] satisfies Partial<Interface>[]) {
  test(`Interfaces preserves untouched addressing ${JSON.stringify(stored)}`, async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem("containd.auth.role", "admin"));
    const iface = { name: "external-test", device: "eth0", ...stored };
    await page.route("**/api/v1/interfaces", (route) => route.fulfill(json([iface])));
    await page.goto("/interfaces");
    const row = page.getByRole("row").filter({
      has: page.getByRole("cell", { name: "external-test", exact: true }),
    });
    await row.getByRole("button", { name: "Edit", exact: true }).click();
    const addresses = row.getByRole("cell").nth(5).locator("input").first();
    await expect(addresses).toHaveValue(stored.addresses?.join(", ") || "");
    if (!stored.addresses?.length && stored.addressMode !== "dhcp") {
      await expect(addresses).toHaveAttribute("placeholder", "192.168.242.2/24, 2001:db8::1/64");
    }
    const request = page.waitForRequest((req) => req.method() === "PATCH" && req.url().endsWith("/interfaces/external-test"));
    await row.getByRole("button", { name: "Save", exact: true }).click();
    const patch = (await request).postDataJSON();
    expect(patch.addressMode).toEqual(stored.addressMode);
    expect(patch.addresses).toEqual(stored.addresses);
    expect(Object.hasOwn(patch, "addressMode")).toBe(Object.hasOwn(stored, "addressMode"));
    expect(Object.hasOwn(patch, "addresses")).toBe(Object.hasOwn(stored, "addresses"));
  });
}

test("Interfaces sends explicit clears when removing an alias and leaving VLAN", async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem("containd.auth.role", "admin"));
  let iface: Interface = {
    name: "vlan-test", alias: "Plant VLAN", device: "eth2", zone: "ot",
    type: "vlan", parent: "eth0", vlanId: 123, addressMode: "static",
    addresses: ["192.0.2.2/24"], gateway: "192.0.2.1",
    access: { mgmt: true, http: false, https: true, ssh: false },
  };
  const writes: Partial<Interface>[] = [];
  await page.route("**/api/v1/interfaces", (route) => route.fulfill(json([iface])));
  await page.route("**/api/v1/interfaces/vlan-test", async (route) => {
    const patch = route.request().postDataJSON() as Partial<Interface>;
    writes.push(patch);
    iface = { ...iface, ...patch };
    await route.fulfill(json(iface));
  });
  const loaded = page.waitForResponse((res) => res.url().endsWith("/api/v1/interfaces"));
  await page.goto("/interfaces");
  await loaded;
  const row = page.getByRole("row").filter({
    has: page.getByRole("cell", { name: "vlan-test", exact: true }),
  });
  await row.getByRole("button", { name: "Edit", exact: true }).click();
  await row.getByPlaceholder("alias (optional)").fill("");
  const inspect = row.getByRole("button", { name: "Inspect", exact: true });
  await expect(inspect).toHaveAttribute("aria-expanded", "true");
  const details = page.locator(`[id="${await inspect.getAttribute("aria-controls")}"]`);
  await details.getByRole("combobox").first().selectOption("physical");
  await row.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByText("Interface staged — commit to apply.", { exact: true })).toBeVisible();
  expect(writes).toEqual([{
    type: "physical", alias: "", members: [], parent: "", vlanId: 0,
    device: "eth2", zone: "ot", addressMode: "static",
    addresses: ["192.0.2.2/24"], gateway: "192.0.2.1",
    access: { mgmt: true, http: false, https: true, ssh: false },
  }]);

  await row.getByRole("button", { name: "Edit", exact: true }).click();
  await row.getByPlaceholder("Network device (e.g. eth0)").fill("");
  await row.getByRole("cell").nth(4).getByRole("combobox").selectOption("");
  await row.getByRole("button", { name: "Save", exact: true }).click();
  await expect.poll(() => writes.length).toBe(2);
  expect(writes[1]).toEqual({ ...writes[0], device: "", zone: "" });
});

test("topology uses OS/Docker fallback in zone subnets, interface details and physical pills", async ({ page }) => {
  const pageErrors: string[] = [];
  page.on("pageerror", (err) => pageErrors.push(String(err)));
  await page.goto("/topology");
  const zone = page.locator('.react-flow__node[data-id="zone-lan"]');
  await expect(zone).toContainText("192.168.242.2/24");
  await expect(zone.getByRole("img", { name: "Detected address" })).toBeVisible();
  const configured = page.locator('.react-flow__node[data-id="zone-wan"]');
  await expect(configured).toContainText("192.0.2.1/24");
  await expect(configured.getByRole("img")).toHaveCount(0);
  await page.locator('.react-flow__node[data-id="fw-main"]').click();
  const detail = page.locator('[class*="ifaceItem"]').filter({ hasText: "eth0" });
  await expect(detail).toContainText("192.168.242.2/24");
  await expect(detail.getByRole("img", { name: "Detected address" })).toBeVisible();
  await page.getByRole("button", { name: "PHYSICAL", exact: true }).click();
  const process = page.getByRole("button", { name: "Application runtime details", exact: true });
  await process.click();
  await expect(process).toHaveAttribute("aria-expanded", "true");
  const pills = page.locator('[class*="layerSectionFull"]').filter({ hasText: "Bound Interfaces (in-process)" });
  const pill = pills.locator("div").filter({ has: page.getByText("eth0", { exact: true }) }).last();
  await expect(pill).toContainText("192.168.242.2/24");
  await expect(pill.getByRole("img", { name: "Detected address" })).toBeVisible();
  expect(pageErrors).toEqual([]);
});


test("topology pairs live data with running config and refreshes both views on commit", async ({ page }) => {
  let address = "192.0.2.1/24";
  let configReads = 0;
  const candidateReads: string[] = [];
  await page.route("**/api/v1/config", (route) => {
    configReads++;
    return route.fulfill(json({ ...defaultConfig, interfaces: [{ ...interfaces[0], addresses: [address] }] }));
  });
  for (const endpoint of ["zones", "interfaces", "firewall/rules", "routing"]) {
    await page.route(`**/api/v1/${endpoint}`, (route) => {
      candidateReads.push(endpoint);
      return route.fulfill(json([]));
    });
  }
  await page.goto("/topology/");
  const zone = page.locator('.react-flow__node[data-id="zone-wan"]');
  await expect(zone).toContainText(address);
  await page.getByRole("button", { name: "PHYSICAL", exact: true }).click();
  const process = page.getByRole("button", { name: "Application runtime details", exact: true });
  await process.click();
  await expect(process).toHaveAttribute("aria-expanded", "true");
  const pills = page.locator('[class*="layerSectionFull"]').filter({ hasText: "Bound Interfaces (in-process)" });
  await expect(pills).toContainText(address);
  const before = configReads;
  address = "198.51.100.1/24";
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("containd:config:committed")));
  await expect(pills).toContainText(address);
  await expect.poll(() => configReads).toBeGreaterThanOrEqual(before + 2);
  await page.getByRole("button", { name: "LOGICAL", exact: true }).click();
  await expect(zone).toContainText(address);
  expect(candidateReads).toEqual([]);
});
