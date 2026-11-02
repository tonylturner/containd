import { expect, test, type Page } from "@playwright/test";
import { observation } from "./fixtures/protection-api";
import type { DataPlaneConfig, EnforcementHealth } from "../lib/api";

const revision = "0123456789abcdef.1";
const nextRevision = `${revision.split(".")[0]}.${Number(revision.split(".")[1]) + 1}`;
const dataplane: DataPlaneConfig = {
  captureInterfaces: ["eth0"], dpiMock: false, enforceTable: "plant",
  dpiEnabled: true, dpiMode: "monitor", dpiProtocols: { http: false },
  dpiIcsProtocols: { modbus: true }, dpiIcsParsing: { modbus: "strict" },
  dpiExclusions: [{ type: "ip", value: "192.0.2.1" }], nflogGroup: 100, nfqueueGroup: 12,
};

async function mockAPI(page: Page, options: {
  enabled?: boolean; state?: EnforcementHealth["state"]; role?: string;
  readFailed?: boolean; action?: string; candidateFailed?: boolean; conflict?: boolean;
} = {}) {
  const role = options.role ?? "admin";
  let config = { ...dataplane, ...(options.enabled === undefined ? {} : { enforcement: options.enabled }) };
  let currentRevision = revision;
  let state = options.state ?? "disabled";
  let readFailed = options.readFailed ?? false;
  const writes: { path: string; body: unknown; revision: string | undefined }[] = [];
  await page.addInitScript(role => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", role);
  }, role);
  await page.route("**/api/v1/**", async route => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (request.method() !== "GET") {
      const body = request.postDataJSON();
      writes.push({ path, body, revision: request.headers()["x-containd-if-revision"] });
      if (path === "/api/v1/dataplane") {
        if (options.conflict) return route.fulfill({ status: 412,
          json: { code: "config_revision_mismatch", error: "stale", currentRevision: nextRevision } });
        config = body;
        currentRevision = nextRevision;
        return route.fulfill({ json: config, headers: { "X-Containd-Revision": currentRevision } });
      }
    }
    if (path === "/api/v1/dataplane" && readFailed) return route.fulfill({ status: 503, json: { error: "read failed" } });
    if (path === "/api/v1/config/candidate" && options.candidateFailed) return route.fulfill({ status: 503, json: { error: "read failed" } });
    const bodies: Record<string, unknown> = {
      "/api/v1/auth/me": { id: "user", role },
      "/api/v1/auth/session": { id: "user", role },
      "/api/v1/health": { status: "ok", enforcement: { state, reason: "" } },
      "/api/v1/dataplane/protection": observation(),
      "/api/v1/dataplane": config,
      "/api/v1/firewall/rules": [],
      "/api/v1/zones": [{ name: "wan" }],
      "/api/v1/firewall/nat": { enabled: false },
      "/api/v1/routing": { routes: [], rules: [], gateways: [] },
      "/api/v1/config/candidate": { firewall: { defaultAction: options.action ?? "DENY" } },
      "/api/v1/config/diff": { changed: false, changedSections: [] },
      "/api/v1/dataplane/ruleset/status": { installed: options.state === "enforcing" },
      "/api/v1/interfaces": [],
      "/api/v1/interfaces/state": [],
    };
    await route.fulfill({ json: bodies[path] ?? {}, headers: { "X-Containd-Revision": currentRevision } });
  });
  return { writes, failRead: () => { readFailed = true; }, setState: (next: EnforcementHealth["state"]) => { state = next; } };
}

async function openFirewall(page: Page) {
  const loaded = Promise.all(["dataplane", "config/candidate", "health"].map(path =>
    page.waitForResponse(`**/api/v1/${path}`)));
  await page.goto("/firewall/");
  await loaded;
}

for (const enabled of [false, true]) {
  test(`${enabled ? "Disable" : "Enable"} stages only the enforcement field at the loaded revision`, async ({ page }) => {
    const mock = await mockAPI(page, { enabled, state: enabled ? "enforcing" : "disabled", action: "ALLOW" });
    await openFirewall(page);
    const label = enabled ? "Disable enforcement" : "Enable enforcement";
    // A page-local unsaved rule must survive staging.
    await page.getByRole("button", { name: "Create rule", exact: true }).click();
    const draft = page.locator("#create-rule-panel input").first();
    await draft.fill("unsaved-rule");
    await page.getByRole("button", { name: label, exact: true }).click();
    const dialog = page.getByRole("dialog");
    await expect(dialog).toContainText(enabled ? "installed ruleset is removed" : "Default action: ALLOW");
    await expect(dialog).toContainText("Commit-confirmed");
    await dialog.getByRole("button", { name: label, exact: true }).click();
    const notice = page.locator("#enforcement").getByRole("status").filter({ hasText: "is staged" });
    await expect(notice).toContainText(`Enforcement ${enabled ? "off" : "on"} is staged`);
    await expect(notice.getByRole("link", { name: "Review changes" })).toHaveAttribute("href", "/config/?tab=diff");
    expect(mock.writes).toEqual([{ path: "/api/v1/dataplane", body: { ...dataplane, enforcement: !enabled }, revision }]);
    await expect(page).toHaveURL(/\/firewall\/$/);
    await expect(draft).toHaveValue("unsaved-rule");
    await expect(page.getByRole("button", { name: /^(Enable|Disable) enforcement$/ })).toHaveCount(0);
  });
}

for (const action of ["DENY", "unknown"]) {
  test(`enable confirmation uses the candidate default ${action}`, async ({ page }) => {
    await mockAPI(page, { candidateFailed: action === "unknown" });
    await openFirewall(page);
    await page.getByRole("button", { name: "Enable enforcement", exact: true }).click();
    await expect(page.getByRole("dialog")).toContainText(`Default action: ${action}`);
  });
}

test("cancel sends nothing, including when false is omitted by the API", async ({ page }) => {
  const mock = await mockAPI(page);
  await openFirewall(page);
  await page.getByRole("button", { name: "Enable enforcement", exact: true }).click();
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  expect(mock.writes).toEqual([]);
});

test("a stale revision uses the existing conflict handling", async ({ page }) => {
  const mock = await mockAPI(page, { enabled: false, conflict: true });
  await openFirewall(page);
  await page.getByRole("button", { name: "Enable enforcement", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Enable enforcement", exact: true }).click();
  await expect(page.getByRole("alert").filter({ hasText: "Configuration changed since you loaded it" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Keep my edits", exact: true })).toBeVisible();
  expect(mock.writes).toHaveLength(1);
  await expect(page.locator("#enforcement")).not.toContainText("is staged");
});

for (const state of ["disabled", "enforcing", "degraded"] as const) {
  test(`candidate difference from ${state} shows direction, not toggle`, async ({ page }) => {
    const enabled = state === "disabled";
    await mockAPI(page, { enabled, state });
    await openFirewall(page);
    await expect(page.locator("#enforcement")).toContainText(`Enforcement ${enabled ? "on" : "off"} is staged`);
    await expect(page.locator("#enforcement").getByRole("link", { name: "Review changes" })).toBeVisible();
    await expect(page.getByRole("button", { name: /^(Enable|Disable) enforcement$/ })).toHaveCount(0);
  });
}

for (const state of ["unknown", "unavailable"] as const) {
  test(`${state} health is not evidence of a staged difference`, async ({ page }) => {
    await mockAPI(page, { enabled: true, state });
    await openFirewall(page);
    await expect(page.locator("#enforcement")).not.toContainText("is staged");
    await expect(page.getByRole("button", { name: "Disable enforcement", exact: true })).toBeVisible();
  });
}

test("once health reports the staged direction active the toggle returns", async ({ page }) => {
  const mock = await mockAPI(page, { enabled: false });
  await page.clock.install();
  await openFirewall(page);
  await page.getByRole("button", { name: "Enable enforcement", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Enable enforcement", exact: true }).click();
  await expect(page.locator("#enforcement")).toContainText("Enforcement on is staged");
  mock.setState("enforcing");
  const polled = page.waitForResponse("**/api/v1/health");
  await page.clock.fastForward(30_000);
  await polled;
  await expect(page.getByRole("button", { name: "Disable enforcement", exact: true })).toBeVisible();
  await expect(page.locator("#enforcement")).not.toContainText("is staged");
});

for (const reason of ["read failure", "view-only"] as const) {
  test(`${reason} has no enforcement action`, async ({ page }) => {
    await mockAPI(page, { readFailed: reason === "read failure", role: reason === "view-only" ? "view" : "admin" });
    await openFirewall(page);
    await expect(page.locator("#enforcement")).toContainText(reason === "read failure" ? "Candidate enforcement unknown" : "Firewall enforcement disabled");
    await expect(page.locator("#enforcement").getByRole("button")).toHaveCount(0);
  });
}

test("failed refresh hides the old toggle and prevents a retained confirmation writing", async ({ page }) => {
  const mock = await mockAPI(page);
  await openFirewall(page);
  await page.getByRole("button", { name: "Enable enforcement", exact: true }).click();
  mock.failRead();
  // Trigger the refresh without dismissing the modal, as a background refresh can.
  await page.getByRole("button", { name: "Refresh", exact: true }).evaluate((el: HTMLButtonElement) => el.click());
  await expect(page.locator("#enforcement")).toContainText("Candidate enforcement unknown");
  await page.getByRole("dialog").getByRole("button", { name: "Enable enforcement", exact: true }).click();
  await expect(page.locator("#enforcement").getByRole("alert")).toContainText("Configuration unavailable");
  expect(mock.writes).toEqual([]);
});

test("390px enforcement card, confirmation and staged notice do not overflow", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await mockAPI(page);
  await openFirewall(page);
  const noOverflow = () => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth);
  expect(await noOverflow()).toBe(true);
  await page.getByRole("button", { name: "Enable enforcement", exact: true }).click();
  await expect(page.getByRole("dialog")).toBeVisible();
  expect(await noOverflow()).toBe(true);
  await page.getByRole("dialog").getByRole("button", { name: "Enable enforcement", exact: true }).click();
  await expect(page.locator("#enforcement")).toContainText("Enforcement on is staged");
  expect(await noOverflow()).toBe(true);
});

test("diagnostics leads to the enforcement control and keeps deployment details", async ({ page }) => {
  await mockAPI(page); // false is omitted on the wire
  const loaded = page.waitForResponse("**/api/v1/dataplane");
  await page.goto("/diagnostics/");
  await loaded;
  const blocks = page.getByRole("region", { name: "Temporary Blocks", exact: true });
  await expect(blocks.getByRole("link", { name: "Enable enforcement on the Firewall page" })).toHaveAttribute("href", "/firewall/#enforcement");
  await expect(blocks.getByRole("button", { name: "Block host", exact: true })).toBeDisabled();
  await blocks.getByText("Deployment details", { exact: true }).click();
  await expect(blocks).toContainText("dataplane.enforcement");
  await expect(blocks).toContainText("CONTAIND_ENFORCE_ENABLED=1");
});
