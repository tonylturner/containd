import { expect, test } from "@playwright/test";

const routes = [
  "/",
  "/alerts",
  "/assets",
  "/audit",
  "/config",
  "/dataplane",
  "/dhcp",
  "/diagnostics",
  "/events",
  "/firewall",
  "/flows",
  "/forbidden",
  "/ics",
  "/ids",
  "/interfaces",
  "/login",
  "/monitoring",
  "/nat",
  "/pcap",
  "/proxies",
  "/routing",
  "/sessions",
  "/system/services",
  "/system/services/av",
  "/system/services/dns",
  "/system/services/ntp",
  "/system/services/syslog",
  "/system/settings",
  "/system/users",
  "/templates",
  "/topology",
  "/vpn",
  "/wizard",
  "/zones",
] as const;

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

const interfaces = [
  {
    name: "wan",
    device: "eth1",
    zone: "wan",
    access: { mgmt: true, http: true, https: true, ssh: true },
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
    name: "wan",
    index: 2,
    up: true,
    mtu: 1500,
    mac: "02:00:00:00:00:01",
    addrs: ["192.168.240.2/24"],
  },
  {
    name: "lan1",
    index: 1,
    up: true,
    mtu: 1500,
    mac: "02:00:00:00:00:02",
    addrs: ["192.168.242.2/24"],
  },
];

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
    dpiMode: "learn",
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
    body: JSON.stringify(body),
  };
}

function responseFor(pathname: string) {
  if (pathname === "/api/v1/auth/me" || pathname === "/api/v1/auth/session") {
    return json(adminUser);
  }
  if (pathname === "/api/v1/dashboard") return json(dashboard);
  if (pathname === "/api/v1/zones") return json(zones);
  if (pathname === "/api/v1/interfaces") return json(interfaces);
  if (pathname === "/api/v1/interfaces/state") return json(interfaceState);
  if (
    pathname === "/api/v1/firewall/rules" ||
    pathname === "/api/v1/firewall/ics-rules"
  ) {
    return json(malformedFirewallRules);
  }
  if (pathname === "/api/v1/audit") return json(auditRecords);
  if (pathname === "/api/v1/firewall/nat") {
    return json({ enabled: false, sourceZones: [], portForwards: [] });
  }
  if (pathname === "/api/v1/config" || pathname === "/api/v1/config/candidate") {
    return json(defaultConfig);
  }
  if (pathname === "/api/v1/config/diff") {
    return json({ hasChanges: false, summary: [], diff: "" });
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
      dpiMode: "learn",
      dpiProtocols: {},
      dpiIcsProtocols: {},
    });
  }
  if (pathname === "/api/v1/dataplane/ruleset") {
    return json({ compiled: "", status: "ok" });
  }
  if (
    pathname === "/api/v1/assets" ||
    pathname === "/api/v1/objects" ||
    pathname === "/api/v1/events" ||
    pathname === "/api/v1/flows" ||
    pathname === "/api/v1/anomalies" ||
    pathname === "/api/v1/conntrack" ||
    pathname === "/api/v1/dhcp/leases" ||
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
  if (pathname === "/api/v1/identities") return json({ mappings: {} });
  if (pathname === "/api/v1/security/conduits") return json({});
  if (pathname === "/api/v1/services/status") return json({});
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
  if (
    pathname === "/api/v1/services/av/defs" ||
    pathname === "/api/v1/services/vpn/openvpn/clients"
  ) {
    return json([]);
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
  if (
    pathname === "/api/v1/system/inspection" ||
    pathname === "/api/v1/system/tls"
  ) {
    return json({});
  }
  if (pathname === "/api/v1/health") {
    return json({ status: "ok", component: "mgmt" });
  }
  return json({});
}

test.beforeEach(async ({ page }) => {
  await page.route("**/api/v1/**", async (route) => {
    const url = new URL(route.request().url());
    if (route.request().method() === "GET") {
      await route.fulfill(responseFor(url.pathname));
      return;
    }
    await route.fulfill(json({ status: "ok" }));
  });
});

for (const path of routes) {
  test(`route smoke ${path}`, async ({ page }) => {
    const consoleErrors: string[] = [];
    const pageErrors: string[] = [];

    page.on("console", (msg) => {
      if (msg.type() === "error") consoleErrors.push(msg.text());
    });
    page.on("pageerror", (err) => {
      pageErrors.push(String(err));
    });

    await page.goto(path);
    await expect(page.locator("body")).toBeVisible();
    await page.waitForLoadState("networkidle");

    expect(pageErrors).toEqual([]);
    expect(consoleErrors).toEqual([]);
  });
}
