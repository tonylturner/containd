import { expect, test } from "@playwright/test";
import { CONFIG_COMMITTED } from "../lib/config-events";

// Exercise unavailable -> real empty -> unavailable after a successful read.
// Each endpoint retains its HTTP failure rather than being mocked as empty.
test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem("containd.auth.role", "admin"));
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const user = { id: "admin-1", username: "admin", role: "admin", mfaRequired: false };
    let body: unknown = {};
    if (path === "/api/v1/auth/me" || path === "/api/v1/auth/session") body = user;
    if (path === "/api/v1/interfaces" || path === "/api/v1/zones" || path === "/api/v1/events") body = [];
    if (path === "/api/v1/pcap/list") body = [];
    if (path === "/api/v1/pcap/config") body = { interfaces: [], zones: [], forwardTargets: [] };
    if (path === "/api/v1/pcap/status") body = { running: false, interfaces: [] };
    if (path === "/api/v1/routing") body = { gateways: [], routes: [], rules: [] };
    if (path === "/api/v1/routing/os") body = { routes: [] };
    if (path === "/api/v1/services/status") body = { faults: [], av: { available: false, error: "engine unavailable" } };
    if (path === "/api/v1/config/diff") body = { changed: false, running: {}, candidate: {} };
    if (path === "/api/v1/dashboard") body = { user, counts: { rules: 0, icsRules: 0 }, health: { hostname: "test" } };
    if (path === "/api/v1/system/stats") body = {
      cpu: { usagePercent: 0 }, memory: { totalBytes: 0, usagePercent: 0 },
      disk: { totalBytes: 0, usagePercent: 0 }, container: { running: true },
      runtime: { uptime: "1m", goroutines: 1 },
    };
    if (["/api/v1/flows", "/api/v1/interfaces/state", "/api/v1/simulation", "/api/v1/diagnostics/iec104"].includes(path)) {
      await route.fulfill({ status: 503, json: { error: "engine unavailable" }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
    } else {
      await route.fulfill({ json: body, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
    }
  });
});

test("flow failure is not an empty flow set and Retry recovers", async ({ page }, testInfo) => {
  let unavailable = true;
  await page.route("**/api/v1/flows?*", (route) => route.fulfill(unavailable
    ? { status: 503, json: { error: "engine flows unavailable" }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } }
    : { json: [], headers: { "X-Containd-Revision": "0123456789abcdef.1" } }));
  await page.goto("/flows/");
  await expect(page.getByRole("status").filter({ hasText: "Flows unavailable" })).toBeVisible();
  await expect(page.getByText("No flows yet", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Total flows: 0", { exact: true })).toHaveCount(0);
  await page.screenshot({ path: testInfo.outputPath("flows-unavailable.png"), fullPage: true });
  unavailable = false;
  await page.getByRole("status").filter({ hasText: "Flows unavailable" }).getByRole("button", { name: "Retry", exact: true }).click();
  await expect(page.getByText("No flows yet", { exact: true })).toBeVisible();
  unavailable = true;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: "Flows unavailable" })).toBeVisible();
  await expect(page.getByText("No flows yet", { exact: true })).toHaveCount(0);
});

test("interface failure differs from a reachable engine with no interfaces", async ({ page }) => {
  let unavailable = true;
  await page.route("**/api/v1/interfaces", (route) => route.fulfill({ json: [{ name: "configured-lan", device: "eth0", addresses: ["192.0.2.1/24"] }], headers: { "X-Containd-Revision": "0123456789abcdef.1" } }));
  await page.route("**/api/v1/interfaces/state", (route) => route.fulfill(unavailable
    ? { status: 503, json: { error: "engine interface state unavailable" }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } }
    : { json: [], headers: { "X-Containd-Revision": "0123456789abcdef.1" } }));
  await page.goto("/interfaces/");
  await expect(page.getByRole("status").filter({ hasText: "Live device information is unavailable" })).toBeVisible();
  await expect(page.getByText("No network devices reported.", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("cell", { name: "configured-lan", exact: true })).toBeVisible();
  unavailable = false;
  await page.getByRole("status").filter({ hasText: "Live device information is unavailable" }).getByRole("button", { name: "Retry", exact: true }).click();
  await expect(page.getByText("No network devices reported.", { exact: true })).toBeVisible();
  await expect(page.getByText("Live device information is unavailable")).toHaveCount(0);
});

test("simulation failure is unknown, not stopped, and Retry recovers", async ({ page }) => {
  let unavailable = true;
  await page.route("**/api/v1/simulation", (route) => route.fulfill(unavailable
    ? { status: 503, json: { error: "engine simulation unavailable" }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } }
    : { json: { running: false }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } }));
  await page.goto("/");
  const state = page.getByRole("status").filter({ hasText: "Simulation unavailable" });
  await expect(state).toBeVisible();
  await expect(page.getByTitle("Start traffic simulation")).toHaveCount(0);
  unavailable = false;
  await state.getByRole("button", { name: "Retry", exact: true }).click();
  await page.getByRole("button", { name: "Tools", exact: true }).click();
  await expect(page.getByTitle("Start traffic simulation")).toBeVisible();
  unavailable = true;
  await page.getByTitle("Start traffic simulation").click();
  await expect(state).toBeVisible();
  await expect(page.getByTitle("Start traffic simulation")).toHaveCount(0);
});

test("monitoring overview does not fabricate zero flow counters", async ({ page }) => {
  await page.goto("/monitoring/");
  await expect(page.getByRole("status").filter({ hasText: "Flows unavailable" })).toBeVisible();
  await expect(page.getByText("No flow apps yet.", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("region", { name: "Endpoints", exact: true }).getByText("Unknown", { exact: true })).toHaveCount(2);
});

test("PCAP discovery distinguishes unavailable, empty and populated state without deleting saved forwarding", async ({ page }) => {
  let phase: "unavailable" | "empty" | "populated" = "unavailable";
  await page.route("**/api/v1/pcap/config", (route) => route.fulfill({ json: {
    interfaces: [], zones: [],
    forwardTargets: [{ interface: "saved-sensor", enabled: true, host: "198.51.100.7", port: 9000, proto: "udp" }],
  }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } }));
  await page.route("**/api/v1/interfaces/state", (route) => route.fulfill(phase === "unavailable"
    ? { status: 503, json: { error: "engine interface state unavailable" }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } }
    : { json: phase === "empty" ? [] : [{ name: "eth9", index: 9, up: true, addrs: ["192.0.2.2/24"] }], headers: { "X-Containd-Revision": "0123456789abcdef.1" } }));
  await page.goto("/dataplane/");
  const unavailable = page.getByRole("status").filter({ hasText: "Live interface information is unavailable" });
  const savedHost = page.locator('input[placeholder="sensor.example.local"][value="198.51.100.7"]');
  await expect(unavailable).toBeVisible();
  await expect(page.getByText("No network devices reported.", { exact: true })).toHaveCount(0);
  await expect(page.getByText(/No firewall interfaces are connected to network devices/)).toHaveCount(0);
  await expect(savedHost).toHaveValue("198.51.100.7");
  phase = "empty";
  await unavailable.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(page.getByText("No network devices reported.", { exact: true })).toBeVisible();
  await expect(unavailable).toHaveCount(0);
  await expect(savedHost).toHaveValue("198.51.100.7");
  phase = "populated";
  await page.reload();
  await expect(page.getByText("eth9 (kernel device)", { exact: true })).toBeVisible();
  await expect(savedHost).toHaveValue("198.51.100.7");
  phase = "unavailable";
  await page.reload();
  await expect(unavailable).toBeVisible();
  await expect(page.getByText("eth9 (kernel device)", { exact: true })).toHaveCount(0);
  await expect(savedHost).toHaveValue("198.51.100.7");
});

test("Auto WAN setup retries unavailable discovery without staging fabricated routes", async ({ page }) => {
  let phase: "unavailable" | "empty" | "populated" = "unavailable";
  const staged: unknown[] = [];
  await page.route("**/api/v1/interfaces", (route) => route.fulfill({ json: [{ name: "wan", device: "eth0", zone: "wan" }], headers: { "X-Containd-Revision": "0123456789abcdef.1" } }));
  await page.route("**/api/v1/interfaces/state", (route) => route.fulfill(phase === "unavailable"
    ? { status: 503, json: { error: "engine interface state unavailable" }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } }
    : { json: phase === "empty" ? [] : [{ name: "eth0", index: 1, up: true, addrs: ["192.0.2.2/24"] }], headers: { "X-Containd-Revision": "0123456789abcdef.1" } }));
  await page.route("**/api/v1/routing", (route) => {
    if (route.request().method() === "POST") {
      const next = route.request().postDataJSON();
      staged.push(next);
      return route.fulfill({ json: next, headers: { "X-Containd-Revision": "0123456789abcdef.1", "X-Containd-Config": "staged" } });
    }
    return route.fulfill({ json: staged.at(-1) ?? { gateways: [], routes: [], rules: [] }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  await page.goto("/routing/");
  const autoWAN = page.getByRole("button", { name: "Auto WAN default", exact: true });
  await autoWAN.click();
  const unavailable = page.getByRole("status").filter({ hasText: "Live interface information is unavailable" });
  await expect(unavailable).toBeVisible();
  await expect(page.getByText(/Could not determine WAN IPv4 address/)).toHaveCount(0);
  expect(staged).toHaveLength(0);
  phase = "empty";
  await unavailable.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(unavailable).toHaveCount(0);
  await expect(page.getByText(/Could not determine WAN IPv4 address/)).toBeVisible();
  expect(staged).toHaveLength(0);
  phase = "populated";
  await autoWAN.click();
  await expect(page.getByText(/Gateway and default route staged/)).toBeVisible();
  expect(staged).toHaveLength(1);
  expect(staged[0]).toMatchObject({
    gateways: [{ name: "wan-gw", address: "192.0.2.1", iface: "eth0" }],
    routes: [{ dst: "default", gateway: "wan-gw", iface: "eth0", table: 0 }],
  });
  phase = "unavailable";
  await autoWAN.click();
  await expect(unavailable).toBeVisible();
  await expect(page.getByText(/Gateway and default route staged/)).toHaveCount(0);
  expect(staged).toHaveLength(1);
});

test("diagnostics keeps interface-state failure local and retries runtime address discovery", async ({ page }) => {
  let phase: "unavailable" | "empty" | "populated" = "unavailable";
  await page.route("**/api/v1/interfaces", (route) => route.fulfill({ json: [
    { name: "lan", device: "eth0", zone: "lan" },
  ], headers: { "X-Containd-Revision": "0123456789abcdef.1" } }));
  await page.route("**/api/v1/interfaces/state", (route) => route.fulfill(phase === "unavailable"
    ? { status: 503, json: { error: "engine interface state unavailable" }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } }
    : { json: phase === "empty" ? [] : [{ name: "eth0", up: true, addrs: ["192.0.2.10/24"] }], headers: { "X-Containd-Revision": "0123456789abcdef.1" } }));
  await page.goto("/diagnostics/");
  const connectivity = page.getByRole("region", { name: "Interface Connectivity", exact: true });
  const unavailable = connectivity.getByRole("status").filter({ hasText: "Interface runtime state unavailable" });
  await expect(unavailable).toBeVisible();
  await expect(connectivity.getByText("No OS interfaces reported.", { exact: true })).toHaveCount(0);
  await expect(connectivity.getByText("Quick pick:", { exact: true })).toHaveCount(0);
  await expect(connectivity.getByRole("option", { name: "lan", exact: true })).toHaveCount(1);
  await expect(page.getByRole("region", { name: "Ping", exact: true }).getByRole("button", { name: "Run", exact: true })).toBeEnabled();
  phase = "empty";
  await unavailable.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(unavailable).toHaveCount(0);
  await expect(connectivity.getByText("No OS interfaces reported.", { exact: true })).toBeVisible();
  await expect(page.getByRole("region", { name: "IEC 104 holdback pressure" }).getByRole("status")).toContainText("IEC 104 diagnostics unavailable");
  phase = "populated";
  await page.reload();
  await expect(connectivity.getByTitle("Use lan OS/Docker IP: 192.0.2.10")).toBeVisible();
  await connectivity.getByTitle("Use lan OS/Docker IP: 192.0.2.10").click();
  await expect(connectivity.getByPlaceholder("host, IP, or interface name")).toHaveValue("192.0.2.10");
  phase = "unavailable";
  await page.reload();
  await expect(unavailable).toBeVisible();
  await expect(connectivity.getByTitle("Use lan OS/Docker IP: 192.0.2.10")).toHaveCount(0);
});

for (const view of ["physical", "logical"] as const) {
  for (const failedEndpoint of ["interfaces", "flows"] as const) {
    test(`${view} topology retries unavailable ${failedEndpoint} without rendering empty or stale runtime data`, async ({ page }) => {
      let phase: "unavailable" | "empty" | "populated" = "unavailable";
      await page.route("**/api/v1/config", (route) => route.fulfill({ json: {
        interfaces: view === "logical" ? [{ name: "lan", device: "eth9", zone: "lan" }] : [],
        zones: [], routing: { gateways: [], routes: [], rules: [] }, firewall: { rules: [] },
      }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } }));
      await page.route("**/api/v1/system/inspection", (route) => route.fulfill({ status: 503, json: { error: "inspection unavailable" }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } }));
      await page.route("**/api/v1/interfaces/state", (route) => route.fulfill(phase === "unavailable" && failedEndpoint === "interfaces"
        ? { status: 503, json: { error: "engine interface state unavailable" }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } }
        : { json: phase === "empty" ? [] : [{ name: "eth9", up: true, mtu: 1500, addrs: ["192.0.2.9/24"] }], headers: { "X-Containd-Revision": "0123456789abcdef.1" } }));
      await page.route("**/api/v1/flows?*", (route) => route.fulfill(phase === "unavailable" && failedEndpoint === "flows"
        ? { status: 503, json: { error: "engine flows unavailable" }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } }
        : { json: phase === "empty" ? [] : [{
          flowId: "flow-1", firstSeen: "2026-01-01T00:00:00Z", lastSeen: "2026-01-01T00:01:00Z", eventCount: 1,
        }], headers: { "X-Containd-Revision": "0123456789abcdef.1" } }));
      await page.goto("/topology/");
      if (view === "physical") await page.getByRole("button", { name: "PHYSICAL", exact: true }).click();
      const unavailable = page.getByRole("alert").filter({ hasText: view === "physical" ? "Physical topology unavailable" : "Logical topology unavailable" });
      const content = view === "physical" ? page.getByText("HOST MACHINE", { exact: true }) : page.locator(".react-flow");
      const sessions = (count: number) => view === "physical"
        ? page.getByText(`${count} SESSIONS`, { exact: true })
        : page.locator(".react-flow__node-firewall").getByText(String(count), { exact: true });
      await expect(unavailable).toBeVisible();
      await expect(content).toHaveCount(0);
      await expect(sessions(0)).toHaveCount(0);
      phase = "empty";
      await (view === "physical" ? unavailable.locator("..") : unavailable).getByRole("button", { name: "Retry", exact: true }).click();
      await expect(unavailable).toHaveCount(0);
      await expect(content).toBeVisible();
      if (view === "physical") {
        const host = page.getByRole("button", { name: "Inspect HOST MACHINE", exact: true });
        await host.click();
        await expect(host).toHaveAttribute("aria-expanded", "true");
      }
      await expect(sessions(0)).toBeVisible();
      await expect(page.getByText("eth9", { exact: true })).toHaveCount(0);
      phase = "populated";
      await page.evaluate((event) => window.dispatchEvent(new CustomEvent(event)), CONFIG_COMMITTED);
      await expect(sessions(1)).toBeVisible();
      if (view === "logical") await page.locator(".react-flow__node-firewall").click();
      await expect(page.getByText("eth9", { exact: true })).toBeVisible();
      if (view === "logical") await expect(page.getByTitle("192.0.2.9/24")).toBeVisible();
      phase = "unavailable";
      await page.evaluate((event) => window.dispatchEvent(new CustomEvent(event)), CONFIG_COMMITTED);
      await expect(unavailable).toBeVisible();
      await expect(content).toHaveCount(0);
      await expect(sessions(1)).toHaveCount(0);
      await expect(page.getByText("eth9", { exact: true })).toHaveCount(0);
    });
  }
}

test("firewall quick-start rejects unavailable WAN discovery before staging any changes", async ({ page }) => {
  let phase: "unavailable" | "empty" | "populated" = "unavailable";
  const writes: { path: string; body: unknown }[] = [];
  await page.route("**/api/v1/interfaces", (route) => route.fulfill({ json: [{ name: "wan", device: "eth0", zone: "wan" }], headers: { "X-Containd-Revision": "0123456789abcdef.1" } }));
  await page.route("**/api/v1/interfaces/state", (route) => route.fulfill(phase === "unavailable"
    ? { status: 503, json: { error: "engine interface state unavailable" }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } }
    : { json: phase === "empty" ? [] : [{ name: "eth0", up: true, addrs: ["192.0.2.2/24"] }], headers: { "X-Containd-Revision": "0123456789abcdef.1" } }));
  for (const [path, initial] of [
    ["/routing", { gateways: [], routes: [], rules: [] }],
    ["/firewall/nat", { enabled: false, sourceZones: [] }],
    ["/firewall/rules", []],
  ] as const) {
    let saved: unknown = initial;
    await page.route(`**/api/v1${path}`, (route) => {
      if (route.request().method() === "POST") {
        saved = route.request().postDataJSON();
        writes.push({ path, body: saved });
        return route.fulfill({ json: saved, headers: { "X-Containd-Revision": "0123456789abcdef.1", "X-Containd-Config": "staged" } });
      }
      return route.fulfill({ json: path === "/firewall/rules" && !Array.isArray(saved) ? [saved] : saved, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
    });
  }
  await page.goto("/firewall/");
  const quickStart = async () => {
    await page.getByRole("button", { name: "Quick start (LAN→WAN)", exact: true }).click();
    await page.getByRole("dialog").getByRole("button", { name: "Continue", exact: true }).click();
  };
  await quickStart();
  await expect(page.getByText(/Interface state unavailable — WAN address discovery failed/)).toBeVisible();
  await expect(page.getByText(/Could not determine WAN IPv4 address/)).toHaveCount(0);
  expect(writes).toHaveLength(0);
  phase = "empty";
  await quickStart();
  await expect(page.getByText(/Could not determine WAN IPv4 address/)).toBeVisible();
  await expect(page.getByText(/Interface state unavailable — WAN address discovery failed/)).toHaveCount(0);
  expect(writes).toHaveLength(0);
  phase = "populated";
  await quickStart();
  await expect(page.getByText(/Outbound quick start staged — commit to apply/)).toBeVisible();
  expect(writes).toHaveLength(3);
  expect(writes[0]).toMatchObject({ path: "/routing", body: { gateways: [{ name: "wan-gw", address: "192.0.2.1" }] } });
  phase = "unavailable";
  await quickStart();
  await expect(page.getByText(/Interface state unavailable — WAN address discovery failed/)).toBeVisible();
  expect(writes).toHaveLength(3);
});

test("VPN runtime distinguishes unavailable interface state from an absent WireGuard interface", async ({ page }) => {
  let phase: "unavailable" | "empty" | "populated" = "unavailable";
  await page.route("**/api/v1/services/vpn", (route) => route.fulfill({ json: {
    wireguard: { enabled: true, interface: "wg0", addressCIDR: "10.8.0.1/24", peers: [] },
    openvpn: { enabled: false, mode: "client" },
  }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } }));
  await page.route("**/api/v1/services/vpn/wireguard/status?*", (route) => route.fulfill({ json: { present: false, peers: [] }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } }));
  await page.route("**/api/v1/interfaces/state", (route) => route.fulfill(phase === "unavailable"
    ? { status: 503, json: { error: "engine interface state unavailable" }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } }
    : { json: phase === "empty" ? [] : [{ name: "wg0", up: true, addrs: ["10.8.0.1/24"] }], headers: { "X-Containd-Revision": "0123456789abcdef.1" } }));
  await page.goto("/vpn/");
  const runtime = page.getByRole("region", { name: "WireGuard runtime", exact: true });
  const unavailable = runtime.getByRole("status").filter({ hasText: "Interface state unavailable" });
  await expect(unavailable).toBeVisible();
  await expect(runtime.getByText("interface state unavailable", { exact: true })).toHaveCount(2);
  await expect(page.getByText("not present", { exact: true })).toHaveCount(0);
  phase = "empty";
  await unavailable.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(unavailable).toHaveCount(0);
  await expect(runtime.getByText("not present", { exact: true })).toBeVisible();
  phase = "populated";
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(runtime.getByText("up", { exact: true })).toBeVisible();
  await expect(runtime.getByText("10.8.0.1/24", { exact: true })).toBeVisible();
  phase = "unavailable";
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(unavailable).toBeVisible();
  await expect(runtime.getByText("10.8.0.1/24", { exact: true })).toHaveCount(0);
  await expect(page.getByText("not present", { exact: true })).toHaveCount(0);
});

test("temporary block guidance names the real enforcement setting and full matching scope", async ({ page }) => {
  await page.route("**/api/v1/dataplane", (route) => route.fulfill({ json: { enforcement: false }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } }));
  await page.goto("/diagnostics/");
  const blocks = page.getByRole("region", { name: "Temporary Blocks", exact: true });
  await expect(blocks).toContainText("Firewall enforcement is off");
  await expect(blocks).not.toContainText("Enable enforcement on the Dataplane page");
  await blocks.getByText("Deployment details", { exact: true }).click();
  await expect(blocks).toContainText("dataplane.enforcement");
  await expect(blocks).toContainText("CONTAIND_ENFORCE_ENABLED=1");
  await expect(blocks).toContainText("any source port");
  await expect(blocks).not.toContainText("5-tuple");
  await expect(blocks.getByRole("button", { name: "Block host", exact: true })).toBeDisabled();
  await expect(blocks.getByRole("button", { name: "Block flow", exact: true })).toBeDisabled();
});
