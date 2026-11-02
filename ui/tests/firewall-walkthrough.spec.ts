import { expect, test, type Page } from "@playwright/test";
import type { ConfigBundle, FirewallRule } from "../lib/api";
import { CONFIG_STAGED } from "../lib/config-events";

const revision = "0123456789abcdef.1";
const nextRevision = `${revision.split(".")[0]}.${Number(revision.split(".")[1]) + 1}`;
const dataplane = {
  captureInterfaces: ["eth0"], dpiMock: false, dpiEnabled: true, dpiMode: "monitor" as const,
  enforcement: true, enforceTable: "plant", nflogGroup: 100, nfqueueGroup: 0,
  dpiProtocols: { http: false }, dpiIcsParsing: { modbus: "strict" as const },
  dpiExclusions: [{ type: "ip" as const, value: "192.0.2.1" }],
};
const rule: FirewallRule = {
  id: "plant-read", action: "ALLOW", sourceZones: ["lan", "engineering"], destZones: ["ot", "safety"],
  protocols: [{ name: "tcp", port: "502" }, { name: "udp", port: "20000" }, { name: "icmp" }],
  ics: { protocol: "modbus", functionCode: [3] },
};

async function mock(page: Page, options: { conflict?: boolean; role?: string; rules?: FirewallRule[] } = {}) {
  const role = options.role ?? "admin";
  let currentRevision = revision;
  let config: ConfigBundle = {
    version: "0.1.10", firewall: { defaultAction: "DENY", rules: options.rules ?? [rule], nat: { enabled: false } },
    zones: [{ name: "lan" }, { name: "engineering" }, { name: "ot" }, { name: "safety" }],
    dataplane, services: { vpn: { privateKey: "<redacted>" } },
  };
  const original = structuredClone(config);
  const writes: { path: string; body: unknown; revision?: string }[] = [];
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
      if (options.conflict || request.headers()["x-containd-if-revision"] !== currentRevision) return route.fulfill({ status: 412,
        json: { code: "config_revision_mismatch", error: "stale", currentRevision: nextRevision } });
      if (path === "/api/v1/config/candidate") config = body;
      if (path === "/api/v1/dataplane") config = { ...config, dataplane: body };
      if (request.method() === "PATCH") {
        config = { ...config, firewall: { ...config.firewall, rules: [{ ...config.firewall!.rules![0], ...body }] } };
      }
      currentRevision = nextRevision;
      return route.fulfill({ json: path.endsWith("/candidate") ? { status: "staged" }
        : path.endsWith("/dataplane") ? config.dataplane : config.firewall!.rules![0],
      headers: { "X-Containd-Revision": currentRevision } });
    }
    const responses: Record<string, unknown> = {
      "/api/v1/auth/me": { id: "user", role },
      "/api/v1/auth/session": { id: "user", role },
      "/api/v1/config/diff": { changed: false, changedSections: [] },
      "/api/v1/config/candidate": config,
      "/api/v1/firewall/rules": config.firewall!.rules,
      "/api/v1/zones": config.zones,
      "/api/v1/dataplane": config.dataplane,
      "/api/v1/firewall/nat": config.firewall!.nat,
      "/api/v1/routing": { gateways: [], routes: [], rules: [] },
      "/api/v1/health": { status: "ok" },
      "/api/v1/dataplane/ruleset/status": { installed: false },
      "/api/v1/firewall/shadow-counters": { available: false, reason: "Not installed" },
    };
    return route.fulfill({ json: responses[path] ?? {}, headers: { "X-Containd-Revision": currentRevision } });
  });
  return { writes, original, config: () => config, publish: () => {
    config = { ...config, services: { changedByAnotherOperator: true } };
    currentRevision = nextRevision;
  } };
}

async function open(page: Page, path = "/firewall/") {
  const loaded = page.waitForResponse("**/api/v1/dataplane");
  await page.goto(path);
  await loaded;
  await expect(page.getByRole("button", { name: "Edit", exact: true }).first()).toBeVisible();
}

test("default confirmation warns for ALLOW, cancels without writes, and preserves other candidate fields", async ({ page }) => {
  const api = await mock(page);
  await open(page);
  const change = page.getByRole("button", { name: "Change default", exact: true });
  await change.click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByLabel("Default action")).toBeEnabled();
  await dialog.getByLabel("Default action").selectOption("ALLOW");
  await expect(dialog.getByRole("alert")).toContainText("ALLOW permits all unmatched traffic");
  await expect(dialog).toContainText("Commit-confirmed");
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
  expect(api.writes).toEqual([]);
  await change.click();
  await expect(dialog.getByLabel("Default action")).toBeEnabled();
  await dialog.getByLabel("Default action").selectOption("ALLOW");
  await dialog.getByRole("button", { name: "Stage default", exact: true }).click();
  await expect(dialog).toHaveCount(0);
  await expect(page.getByRole("row", { name: "Default policy" })).toContainText("Unmatched traffic allowed");
  expect(api.writes).toEqual([{ path: "/api/v1/config/candidate", revision,
    body: { ...api.original, firewall: { ...api.original.firewall, defaultAction: "ALLOW" } } }]);
  // Reopening uses the new revision and allows the explicit restrictive value.
  await change.click();
  await expect(dialog.getByLabel("Default action")).toHaveValue("ALLOW");
  await dialog.getByLabel("Default action").selectOption("DENY");
  await expect(dialog).toContainText("DENY drops unmatched traffic");
  await dialog.getByRole("button", { name: "Stage default", exact: true }).click();
  await expect(dialog).toHaveCount(0);
  expect(api.writes[1]).toMatchObject({ revision: nextRevision, body: { firewall: { defaultAction: "DENY" } } });
});

test("default 412 keeps the choice visible and requires review without applying", async ({ page }) => {
  const api = await mock(page, { conflict: true });
  await open(page);
  await page.getByRole("button", { name: "Change default", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByLabel("Default action")).toBeEnabled();
  await dialog.getByLabel("Default action").selectOption("ALLOW");
  await dialog.getByRole("button", { name: "Stage default", exact: true }).click();
  await expect(dialog).toContainText("Configuration changed");
  await expect(dialog.getByLabel("Default action")).toHaveValue("ALLOW");
  expect(api.writes).toHaveLength(1);
  expect(api.config().firewall!.defaultAction).toBe("DENY");
  await expect(dialog.getByRole("button", { name: "Stage default", exact: true })).toHaveCount(0);
  await dialog.getByRole("button", { name: "Close", exact: true }).click();
  expect(api.writes).toHaveLength(1);
});

test("the accepted empty default action stages the system DENY default", async ({ page }) => {
  const api = await mock(page);
  await open(page);
  await page.getByRole("button", { name: "Change default", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByLabel("Default action")).toBeEnabled();
  await dialog.getByLabel("Default action").selectOption("");
  await dialog.getByRole("button", { name: "Stage default", exact: true }).click();
  await expect(dialog).toHaveCount(0);
  expect(api.writes[0]).toMatchObject({ revision, body: { firewall: { defaultAction: "" } } });
  await expect(page.getByRole("row", { name: "Default policy" }).getByRole("status")).toHaveText("DENY");
});

test("background refresh cannot rebase an open default confirmation over another operator's change", async ({ page }) => {
  const api = await mock(page);
  await open(page);
  await page.getByRole("button", { name: "Change default", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByLabel("Default action")).toBeEnabled();
  await dialog.getByLabel("Default action").selectOption("ALLOW");
  api.publish();
  const refreshed = page.waitForResponse("**/api/v1/config/candidate");
  await page.evaluate(event => window.dispatchEvent(new CustomEvent(event)), CONFIG_STAGED);
  await refreshed;
  await expect(dialog.getByLabel("Default action")).toHaveValue("ALLOW");
  await dialog.getByRole("button", { name: "Stage default", exact: true }).click();
  await expect(dialog).toContainText("Configuration changed");
  expect(api.writes).toHaveLength(1);
  expect(api.writes[0].revision).toBe(revision);
  expect(api.config().services).toEqual({ changedByAnotherOperator: true });
});

test("inline link opens setup; Enforce without inline offers prerequisite rather than sending a rejected write", async ({ page }) => {
  const api = await mock(page);
  await open(page);
  await page.getByRole("combobox", { name: "ICS DPI Mode", exact: true }).selectOption("enforce");
  const alert = page.getByRole("alert").filter({ hasText: "Enforce requires inline inspection" });
  await expect(alert).toBeVisible();
  expect(api.writes).toEqual([]);
  await alert.getByRole("link", { name: "Set up inline inspection" }).click();
  const setup = page.getByRole("region", { name: "Inline inspection", exact: true });
  await expect(setup).toBeInViewport();
  await setup.getByLabel("Inline queue (NFQUEUE)").fill("205");
  await setup.getByLabel("Packet logging group (NFLOG)").fill("205");
  await setup.getByRole("button", { name: "Stage inline inspection", exact: true }).click();
  await expect(setup.getByRole("status")).toContainText("staged");
  expect(api.writes).toEqual([{ path: "/api/v1/dataplane", revision,
    body: { ...dataplane, nfqueueGroup: 205, nflogGroup: 205 } }]);
  await page.getByRole("combobox", { name: "ICS DPI Mode", exact: true }).selectOption("enforce");
  await expect.poll(() => api.writes.length).toBe(2);
  expect(api.writes[1]).toMatchObject({ revision: nextRevision, body: { dpiMode: "enforce", nfqueueGroup: 205 } });
});

test("inline setup preserves the draft after 412 and validates queue bounds", async ({ page }) => {
  const api = await mock(page, { conflict: true });
  await open(page, "/firewall/#inline-inspection");
  const setup = page.getByRole("region", { name: "Inline inspection", exact: true });
  await setup.getByLabel("Inline queue (NFQUEUE)").fill("0");
  await setup.getByRole("button", { name: "Stage inline inspection", exact: true }).click();
  await expect(setup.getByRole("alert")).toContainText("1–65535");
  expect(api.writes).toHaveLength(0);
  await setup.getByLabel("Inline queue (NFQUEUE)").fill("207");
  await setup.getByRole("button", { name: "Stage inline inspection", exact: true }).click();
  await expect(setup).toContainText("Configuration changed");
  await expect(setup.getByLabel("Inline queue (NFQUEUE)")).toHaveValue("207");
  await expect(setup.getByRole("button", { name: "Stage inline inspection", exact: true })).toBeDisabled();
  await expect(setup.getByRole("button", { name: "Keep my edits", exact: true })).toHaveCount(0);
  expect(api.writes).toHaveLength(1);
  expect(api.config().dataplane!.nfqueueGroup).toBe(0);
});

test("global Enforce remains stageable without inline when every ICS rule explicitly monitors", async ({ page }) => {
  const api = await mock(page, { rules: [{ ...rule, ics: { ...rule.ics, mode: "monitor" } }] });
  await open(page);
  await page.getByRole("combobox", { name: "ICS DPI Mode", exact: true }).selectOption("enforce");
  await expect.poll(() => api.writes.length).toBe(1);
  expect(api.writes[0]).toMatchObject({ path: "/api/v1/dataplane", revision, body: { dpiMode: "enforce", nfqueueGroup: 0 } });
});

for (const entry of ["form", "prerequisite"]) {
  test(`firewall ${entry} link dismisses the editor and reveals inline setup without staging the rule`, async ({ page }) => {
    const api = await mock(page);
    await open(page, entry === "prerequisite" ? "/firewall/#inline-inspection" : "/firewall/");
    const disclosure = page.getByRole("button", { name: /^DPI settings/ });
    await expect(disclosure).toHaveAttribute("aria-expanded", "true");
    await disclosure.click();
    await page.getByRole("button", { name: "Edit", exact: true }).click();
    const heading = page.getByRole("heading", { name: `Edit rule ${rule.id}` });
    const form = heading.locator("../..");
    if (entry === "prerequisite") await form.getByRole("combobox", { name: "Rule Mode", exact: true }).selectOption("enforce");
    const link = entry === "prerequisite" ? form.getByRole("alert").getByRole("link", { name: "Set up inline inspection" })
      : form.getByRole("link", { name: "Set up inline inspection" });
    await link.click();
    await expect(heading).toHaveCount(0);
    const setup = page.getByRole("region", { name: "Inline inspection", exact: true });
    await expect(setup).toBeVisible();
    await expect(setup).toBeInViewport();
    expect(api.writes).toEqual([]);
  });
}

test("complete rule match lists round trip and allow editing and removing every entry", async ({ page }) => {
  const api = await mock(page);
  await open(page);
  await page.getByRole("button", { name: "Edit", exact: true }).click();
  const form = page.getByRole("heading", { name: `Edit rule ${rule.id}` }).locator("../..");
  await expect(form.getByLabel("Source zone 2", { exact: true })).toHaveValue("engineering");
  await expect(form.getByLabel("Protocol 3", { exact: true })).toHaveValue("icmp");
  await form.getByLabel("Source zone 2", { exact: true }).selectOption("ot");
  await form.getByRole("button", { name: "Remove dest zone 1", exact: true }).click();
  await form.getByRole("button", { name: "Add dest zone", exact: true }).click();
  await form.getByLabel("Dest zone 2", { exact: true }).selectOption("engineering");
  await form.getByLabel("Protocol 2 port/range", { exact: true }).fill("53");
  await form.getByRole("button", { name: "Remove protocol 3", exact: true }).click();
  await form.getByRole("button", { name: "Add protocol", exact: true }).click();
  await form.getByLabel("Protocol 3", { exact: true }).selectOption("udp");
  await form.getByLabel("Protocol 3 port/range", { exact: true }).fill("123");
  await form.getByRole("button", { name: "Save changes", exact: true }).click();
  await expect(page.getByRole("heading", { name: `Edit rule ${rule.id}` })).toHaveCount(0);
  expect(api.writes[0]).toMatchObject({ revision, body: {
    sourceZones: ["lan", "ot"], destZones: ["safety", "engineering"],
    protocols: [{ name: "tcp", port: "502" }, { name: "udp", port: "53" }, { name: "udp", port: "123" }],
  } });
  await page.getByRole("button", { name: "Edit", exact: true }).click();
  await expect(form.getByLabel("Source zone 2", { exact: true })).toHaveValue("ot");
  await expect(form.getByLabel("Dest zone 2", { exact: true })).toHaveValue("engineering");
  await expect(form.getByLabel("Protocol 3 port/range", { exact: true })).toHaveValue("123");
});

test("ICS cards keep all fields and Edit reachable at 390px, with a link to inline setup", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const api = await mock(page);
  await open(page, "/ics/");
  const row = page.getByRole("row").filter({ has: page.getByRole("cell", { name: rule.id, exact: true }) });
  await row.scrollIntoViewIfNeeded();
  const edit = row.getByRole("button", { name: "Edit", exact: true });
  await expect(edit).toBeInViewport();
  const box = await edit.boundingBox();
  expect(box!.x + box!.width).toBeLessThanOrEqual(390);
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
  expect(await row.evaluate(element => element.scrollWidth <= element.clientWidth)).toBe(true);
  await expect(row).toContainText("Observation only — non-blocking");
  await expect(row.locator("[data-label]")).toHaveCount(7);
  await expect(page.getByRole("link", { name: "Set up inline inspection", exact: true })).toHaveAttribute("href", "/firewall/#inline-inspection");
  await edit.click();
  await page.getByRole("combobox", { name: "Safety mode", exact: true }).selectOption("enforce");
  await expect(page.getByRole("alert").filter({ hasText: "Enforce requires inline inspection" })).toBeVisible();
  expect(api.writes).toEqual([]);
});
