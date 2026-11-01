import { expect, test, type Page } from "@playwright/test";

// The antivirus page edits the scan selection of the scanning gate and shows
// whether the gate is scanning. The API is mocked: saves echo their body so
// the test can inspect the staged payload.

const admin = { id: "admin-1", username: "containd", role: "admin", mfaRequired: false };
const zones = [{ name: "lan", alias: "Plant" }, { name: "wan" }, { name: "ot" }];
const assets = [
  { id: "plc-1", name: "PLC 1", zone: "ot", ips: ["10.0.0.5"] },
  { id: "hmi-2", name: "HMI 2", zone: "ot" },
];
const meter = { sparkline: [], count: 0, rate_per_min: 0, errors_sparkline: [], errors_count: 0, errors_rate_per_min: 0 };

const baseConfig = {
  enabled: true,
  mode: "clamav",
  failPolicy: "closed",
  httpDownload: true,
  scan: { include: [{ sourceZones: ["lan"], destPorts: ["80"] }], downloadMode: "hold" },
};

const listeners = [
  { address: "127.0.0.1:18100", masquerade: false, up: true },
  { address: "[::1]:18100", masquerade: false, up: true },
];

function gate(overrides: Record<string, unknown> = {}) {
  return {
    state: "open", enabled: true, fail_policy: "closed", admit: "open",
    listeners, scanner: { ready: true }, connections: 3, ...overrides,
  };
}

type Mock = { requests: { method: string; path: string; body: unknown }[] };

async function mockAPI(page: Page, options: { gate?: Record<string, unknown>; fail?: string; config?: Record<string, unknown> } = {}): Promise<Mock> {
  const mock: Mock = { requests: [] };
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "admin");
  });
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === "/api/v1/auth/me" || path === "/api/v1/auth/session") {
      await route.fulfill({ json: admin, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
      return;
    }
    if (request.method() === "GET") {
      const body = path === "/api/v1/services/av" ? { ...baseConfig, ...options.config }
        : path === "/api/v1/services/status" ? { faults: [], av: { available: true, enabled: true, mode: "clamav", ready: true, ...meter, gate: options.gate ?? gate() } }
          : path === "/api/v1/zones" ? zones
            : path === "/api/v1/assets" ? assets
              : path === "/api/v1/services/av/defs" ? { path: "/data/clamav/custom", files: [], definitions: [] }
                : path === "/api/v1/config/diff" ? { changed: false, changedSections: [] }
                  : {};
      await route.fulfill({ json: body, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
      return;
    }
    const body = request.postDataJSON();
    mock.requests.push({ method: request.method(), path, body });
    if (options.fail) {
      await route.fulfill({ status: 400, json: { error: options.fail }, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
      return;
    }
    await route.fulfill({ json: body, headers: { "X-Containd-Revision": "0123456789abcdef.1" } });
  });
  return mock;
}

async function openPage(page: Page) {
  // The definitions list is the last request of a refresh, so the zones and assets are in by then.
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/services/av/defs");
  await page.goto("/system/services/av/");
  await loaded;
}

const gateBlock = (page: Page) => page.getByTestId("gate-status");

test("the saved payload round-trips the scan selection and carries no failOpenIcs", async ({ page }) => {
  const mock = await mockAPI(page);
  await openPage(page);
  await expect(page.getByText("ICS fail-open")).toHaveCount(0);
  await expect(page.getByLabel("Always fail open for ICS traffic")).toHaveCount(0);

  const include = page.getByTestId("scan-include").first();
  await expect(include.getByRole("group", { name: "Source zones" }).getByLabel("Plant (lan)")).toBeChecked();
  await include.getByRole("group", { name: "Destination zones" }).getByLabel("wan", { exact: true }).check();
  await include.getByLabel("Destination ports").fill("80, 8080");

  await page.getByRole("button", { name: "Add exclude" }).click();
  const exclude = page.getByTestId("scan-exclude").first();
  await expect(exclude.getByText("Set at least one field")).toBeVisible();
  await exclude.getByLabel("Sources").fill("10.0.0.0/24");
  await expect(exclude.getByText("Set at least one field")).toHaveCount(0);

  await page.getByLabel("Download mode").selectOption("stream_tail");
  await page.getByRole("group", { name: "ICS zones" }).getByLabel("ot", { exact: true }).check();
  await page.getByRole("group", { name: "ICS assets" }).getByLabel("PLC 1").check();
  await page.getByLabel("Scan HTTP uploads").check();

  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByRole("status", { name: "Save state" })).toHaveText("State: staged — commit to apply.");

  expect(mock.requests.map((r) => r.path)).toEqual(["/api/v1/services/av"]);
  const body = mock.requests[0].body as Record<string, unknown>;
  expect(body).not.toHaveProperty("failOpenIcs");
  expect(body.httpDownload).toBe(true);
  expect(body.httpUpload).toBe(true);
  expect(body.scan).toEqual({
    include: [{ sourceZones: ["lan"], destZones: ["wan"], destPorts: ["80", "8080"] }],
    exclude: [{ sources: ["10.0.0.0/24"] }],
    downloadMode: "stream_tail",
    icsZones: ["ot"],
    icsAssets: ["plc-1"],
  });
});

test("an ICS decoder port is flagged before the save", async ({ page }) => {
  await mockAPI(page);
  await openPage(page);
  const include = page.getByTestId("scan-include").first();
  await include.getByLabel("Destination ports").fill("80, 500-510");
  await expect(include.getByText("Port range 500-510 includes reserved industrial port 502 (Modbus); choose different ports.")).toBeVisible();
  await include.getByLabel("Destination ports").fill("80");
  await expect(include.getByText(/includes reserved industrial port/)).toHaveCount(0);
});

test("advanced scanner settings retain protocol and path controls", async ({ page }) => {
  await mockAPI(page, { config: { clamav: {
    socketPath: "/run/clamav/clamd.sock", customDefsPath: "/data/clamav/custom", freshclamEnabled: true,
  } } });
  await openPage(page);
  await expect(page.getByText("Socket path", { exact: true })).not.toBeVisible();
  await page.getByText("Advanced local scanner settings", { exact: true }).click();
  await expect(page.getByText("Socket path", { exact: true })).toBeVisible();
  await expect(page.getByPlaceholder("/run/clamav/clamd.sock")).toBeVisible();
  await page.getByText("Advanced remote scanner settings", { exact: true }).click();
  await expect(page.getByText(/REQMOD for uploads, RESPMOD for downloads/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Add server", exact: true })).toBeVisible();
});

test("a refused scan selection shows the server's validation error", async ({ page }) => {
  const error = 'services.av.scan.include[0].destPorts "502" covers ICS decoder port modbus/502; scan selection may not include an ICS decoder port';
  await mockAPI(page, { fail: error });
  await openPage(page);
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expect(page.getByRole("status", { name: "Save state" })).toHaveText("State: error");
  await expect(page.getByText(error).first()).toBeVisible();
});

test("an open gate reports that it scans", async ({ page }) => {
  await mockAPI(page);
  await openPage(page);
  await expect(gateBlock(page).getByRole("status")).toHaveText("open");
  await expect(gateBlock(page).getByText("Scanning the selected HTTP traffic.")).toBeVisible();
  await gateBlock(page).getByText("Scan-path details", { exact: true }).click();
  await expect(gateBlock(page).getByText("Listeners up: 2/2")).toBeVisible();
  await expect(gateBlock(page).getByText("Active connections: 3")).toBeVisible();
  await expect(gateBlock(page).getByText("not scanning")).toHaveCount(0);
});

test("a starting scanner is pending, not a failure", async ({ page }) => {
  await mockAPI(page, { gate: gate({ state: "pending", scanner: { ready: false, error: "clamd is starting" } }) });
  await openPage(page);
  await expect(gateBlock(page).getByRole("status")).toHaveText("pending");
  await expect(gateBlock(page).getByRole("status")).toHaveClass(/badge-warning/);
  await expect(gateBlock(page).getByText("waiting for the scanner to become ready")).toBeVisible();
  await expect(gateBlock(page).getByText("Scanner ready: no (clamd is starting)")).toBeVisible();
  await expect(gateBlock(page).locator(".text-red-400")).toHaveCount(0);
});

test("a refusing gate is a failure and names the listener and routing faults", async ({ page }) => {
  await mockAPI(page, {
    gate: gate({
      state: "refuse", admit: "refuse",
      listeners: [listeners[0], { address: "[::1]:18100", masquerade: false, up: false, error: "bind: address already in use" }],
      routing_error: "fwmark rule: operation not permitted",
      admit_error: "gate_admit: nft apply failed",
      warning: "zone \"ot\" has no interface bound to it",
    }),
  });
  await openPage(page);
  // Refuse is a failure: the gate is down and the closed policy resets the selected traffic.
  await expect(gateBlock(page).getByRole("status")).toHaveText("refusing");
  await expect(gateBlock(page).getByRole("status")).toHaveClass(/badge-critical/);
  await expect(gateBlock(page).getByText("selected connections are refused; ICS endpoints pass")).toBeVisible();
  await expect(gateBlock(page).getByText("Listener [::1]:18100: down — bind: address already in use")).toBeVisible();
  await expect(gateBlock(page).getByText("Routing: fwmark rule: operation not permitted")).toBeVisible();
  await expect(gateBlock(page).getByText("Admission: gate_admit: nft apply failed")).toBeVisible();
  await expect(gateBlock(page).getByText("zone \"ot\" has no interface bound to it")).toBeVisible();
  await gateBlock(page).getByText("Scan-path details", { exact: true }).click();
  await expect(gateBlock(page).getByText("Listeners up: 1/2")).toBeVisible();
});

test("a passing gate says it is not scanning", async ({ page }) => {
  await mockAPI(page, { gate: gate({ state: "pass", admit: "pass", fail_policy: "open", listeners: [{ ...listeners[0], up: false, unavailable: true }] }) });
  await openPage(page);
  await expect(gateBlock(page).getByRole("status")).toHaveText("passing");
  await expect(gateBlock(page).getByRole("status")).toHaveClass(/badge-warning/);
  await expect(gateBlock(page).getByText("not scanning", { exact: true })).toBeVisible();
  await expect(gateBlock(page).getByText("selected connections pass unscanned")).toBeVisible();
  await gateBlock(page).getByText("Scan-path details", { exact: true }).click();
  await expect(gateBlock(page).getByText("Listener 127.0.0.1:18100: unavailable on this host")).toBeVisible();
});

test("an off gate is neutral", async ({ page }) => {
  await mockAPI(page, { gate: gate({ state: "off", enabled: false, admit: "refuse", listeners: [], connections: 0 }) });
  await openPage(page);
  await expect(gateBlock(page).getByRole("status")).toHaveText("off");
  await expect(gateBlock(page).getByText("Off: firewall enforcement is off.")).toBeVisible();
  await gateBlock(page).getByText("Scan-path details", { exact: true }).click();
  await expect(gateBlock(page).getByText("Listeners up: 0/0")).toBeVisible();
});

for (const config of [
  { mode: "icap" },
  { icap: { servers: [{ address: "scanner.example:1344", service: "avscan", useTls: true }] } },
  { clamav: { socketPath: "/custom/clamd.sock" } },
  { clamav: { customDefsPath: "/custom/defs" } },
  { clamav: { updateSchedule: "4h" } },
  { clamav: { freshclamEnabled: false } },
]) {
  test(`advanced scanner settings reveal mode-required or non-default configuration ${JSON.stringify(config)}`, async ({ page }) => {
    const mock = await mockAPI(page, { config });
    await openPage(page);
    const summary = "clamav" in config ? "Advanced local scanner settings" : "Advanced remote scanner settings";
    const details = page.locator("details").filter({ has: page.getByText(summary, { exact: true }) });
    await expect(details).toHaveAttribute("open", "");
    expect(mock.requests).toEqual([]);
  });
}

test("fail policy options name the scanner-unavailable condition and retain API values", async ({ page }) => {
  const mock = await mockAPI(page);
  await openPage(page);
  for (const [value, label] of [["open", "Allow unscanned traffic when the scanner is unavailable"], ["closed", "Block selected traffic when the scanner is unavailable"]]) {
    const option = page.getByRole("option", { name: label, exact: true });
    await expect(option).toHaveAttribute("value", value);
    await page.locator("select").filter({ has: option }).selectOption(value);
    await page.getByRole("button", { name: "Save", exact: true }).click();
    await expect(page.getByRole("status", { name: "Save state" })).toHaveText("State: staged — commit to apply.");
    expect((mock.requests.at(-1)?.body as Record<string, unknown>).failPolicy).toBe(value);
  }
});
