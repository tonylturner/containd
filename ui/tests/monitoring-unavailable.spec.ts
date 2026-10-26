import { expect, test } from "@playwright/test";

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
    if (path === "/api/v1/config/diff") body = { changed: false, running: {}, candidate: {} };
    if (path === "/api/v1/dashboard") body = { user, counts: { rules: 0, icsRules: 0 }, health: { hostname: "test" } };
    if (path === "/api/v1/system/stats") body = {
      cpu: { usagePercent: 0 }, memory: { totalBytes: 0, usagePercent: 0 },
      disk: { totalBytes: 0, usagePercent: 0 }, container: { running: true },
      runtime: { uptime: "1m", goroutines: 1 },
    };
    if (["/api/v1/flows", "/api/v1/interfaces/state", "/api/v1/simulation"].includes(path)) {
      await route.fulfill({ status: 503, json: { error: "engine unavailable" } });
    } else {
      await route.fulfill({ json: body });
    }
  });
});

test("flow failure is not an empty flow set and Retry recovers", async ({ page }, testInfo) => {
  let unavailable = true;
  await page.route("**/api/v1/flows?*", (route) => route.fulfill(unavailable
    ? { status: 503, json: { error: "engine flows unavailable" } }
    : { json: [] }));
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
  await page.route("**/api/v1/interfaces", (route) => route.fulfill({ json: [{ name: "configured-lan", device: "eth0", addresses: ["192.0.2.1/24"] }] }));
  await page.route("**/api/v1/interfaces/state", (route) => route.fulfill(unavailable
    ? { status: 503, json: { error: "engine interface state unavailable" } }
    : { json: [] }));
  await page.goto("/interfaces/");
  await expect(page.getByRole("status").filter({ hasText: "Interface runtime state unavailable" })).toBeVisible();
  await expect(page.getByText("No OS interfaces reported.", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("cell", { name: "configured-lan", exact: true })).toBeVisible();
  unavailable = false;
  await page.getByRole("status").filter({ hasText: "Interface runtime state unavailable" }).getByRole("button", { name: "Retry", exact: true }).click();
  await expect(page.getByText("No OS interfaces reported.", { exact: true })).toBeVisible();
  await expect(page.getByText("Interface runtime state unavailable")).toHaveCount(0);
});

test("simulation failure is unknown, not stopped, and Retry recovers", async ({ page }) => {
  let unavailable = true;
  await page.route("**/api/v1/simulation", (route) => route.fulfill(unavailable
    ? { status: 503, json: { error: "engine simulation unavailable" } }
    : { json: { running: false } }));
  await page.goto("/");
  const state = page.getByRole("status").filter({ hasText: "Simulation unavailable" });
  await expect(state).toBeVisible();
  await expect(page.getByTitle("Start traffic simulation")).toHaveCount(0);
  unavailable = false;
  await state.getByRole("button", { name: "Retry", exact: true }).click();
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
  await expect(page.getByText("Unknown", { exact: true })).toHaveCount(2);
});

test("PCAP discovery distinguishes unavailable, empty and populated state without deleting saved forwarding", async ({ page }) => {
  let phase: "unavailable" | "empty" | "populated" = "unavailable";
  await page.route("**/api/v1/pcap/config", (route) => route.fulfill({ json: {
    interfaces: [], zones: [],
    forwardTargets: [{ interface: "saved-sensor", enabled: true, host: "198.51.100.7", port: 9000, proto: "udp" }],
  } }));
  await page.route("**/api/v1/interfaces/state", (route) => route.fulfill(phase === "unavailable"
    ? { status: 503, json: { error: "engine interface state unavailable" } }
    : { json: phase === "empty" ? [] : [{ name: "eth9", index: 9, up: true, addrs: ["192.0.2.2/24"] }] }));
  await page.goto("/dataplane/");
  const unavailable = page.getByRole("status").filter({ hasText: "Interface runtime state unavailable" });
  const savedHost = page.locator('input[placeholder="sensor.example.local"][value="198.51.100.7"]');
  await expect(unavailable).toBeVisible();
  await expect(page.getByText("No OS interfaces reported.", { exact: true })).toHaveCount(0);
  await expect(page.getByText(/No firewall interfaces are bound to OS devices/)).toHaveCount(0);
  await expect(savedHost).toHaveValue("198.51.100.7");
  phase = "empty";
  await unavailable.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(page.getByText("No OS interfaces reported.", { exact: true })).toBeVisible();
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
  await page.route("**/api/v1/interfaces", (route) => route.fulfill({ json: [{ name: "wan", device: "eth0", zone: "wan" }] }));
  await page.route("**/api/v1/interfaces/state", (route) => route.fulfill(phase === "unavailable"
    ? { status: 503, json: { error: "engine interface state unavailable" } }
    : { json: phase === "empty" ? [] : [{ name: "eth0", index: 1, up: true, addrs: ["192.0.2.2/24"] }] }));
  await page.route("**/api/v1/routing", (route) => {
    if (route.request().method() === "POST") {
      const next = route.request().postDataJSON();
      staged.push(next);
      return route.fulfill({ json: next, headers: { "X-Containd-Config": "staged" } });
    }
    return route.fulfill({ json: staged.at(-1) ?? { gateways: [], routes: [], rules: [] } });
  });
  await page.goto("/routing/");
  const autoWAN = page.getByRole("button", { name: "Auto WAN default", exact: true });
  await autoWAN.click();
  const unavailable = page.getByRole("status").filter({ hasText: "Interface runtime state unavailable" });
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
