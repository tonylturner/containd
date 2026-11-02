import type { Page } from "@playwright/test";
import { expect, test } from "./fixtures/topology-test";

import { summarizeTargets, targetSummaryText } from "../app/topology/security-summary";
import type { Conduit, Zone } from "../lib/api";
import { mapZone, SR_DEFS } from "../lib/security-scoring";

// The security view's overview counts every zone below its SL target, not
// only the zones shown in the matrix, scored as the matrix scores them.

// Without conduits a zone has no explicit policy (SR-5.1), so checks indicate
// SL 0 unless overrides mark its requirement checks as passing.
const metUpTo = (sl: number) => Object.fromEntries(SR_DEFS.filter((sr) => sr.sl <= sl).map((sr) => [sr.id, true]));
const zones = [
  { name: "it", slTarget: 0 },
  { name: "ot", slTarget: 2 },
  { name: "dmz", slTarget: 1, slOverrides: metUpTo(1) },
  { name: "scada", slTarget: 3, slOverrides: metUpTo(1) },
];

test("zones below their target are counted across all zones", () => {
  const summary = summarizeTargets(zones.map(mapZone), []);
  expect(summary).toEqual({
    total: 4,
    below: [
      { id: "ot", name: "OT", sl_a: 0, sl_t: 2 },
      { id: "scada", name: "SCADA", sl_a: 1, sl_t: 3 },
    ],
  });
  expect(targetSummaryText(summary)).toBe("2 of 4 zones have unmet SL target checks:");
  expect(targetSummaryText(summarizeTargets([zones[0], zones[2]].map(mapZone), []))).toBe("All 2 zones pass SL target checks.");
  expect(targetSummaryText(summarizeTargets([mapZone(zones[0])], []))).toBe("The zone passes its SL target checks.");
  expect(targetSummaryText(summarizeTargets([mapZone(zones[1])], []))).toBe("1 of 1 zone has unmet SL target checks:");
  expect(targetSummaryText(summarizeTargets([], []))).toBe("No zones configured.");
});

async function serveSecurity(page: Page, zoneList: Zone[], conduits: Conduit[] = []) {
  let counter = 1;
  const revision = () => `0123456789abcdef.${counter}`;
  const updates: { name: string; body: unknown }[] = [];
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (route.request().method() === "PATCH" && path.startsWith("/api/v1/zones/")) {
      const body = route.request().postDataJSON();
      const expected = route.request().headers()["x-containd-if-revision"];
      if (!expected) return route.fulfill({ status: 428, json: { error: "revision required", code: "config_revision_required" } });
      if (expected !== revision()) return route.fulfill({ status: 412, json: { error: "configuration changed", code: "config_revision_mismatch", currentRevision: revision() } });
      const name = decodeURIComponent(path.split("/").pop()!);
      const zone = zoneList.find((z) => z.name === name)!;
      Object.assign(zone, body);
      updates.push({ name, body });
      counter++;
      return route.fulfill({ json: zone, headers: { "X-Containd-Revision": revision(), "X-Containd-Config": "staged" } });
    }
    const body = path === "/api/v1/auth/me" || path === "/api/v1/auth/session" ? { id: "admin", username: "containd", role: "admin" }
      : path === "/api/v1/zones" ? zoneList
        : path === "/api/v1/security/conduits" ? conduits
          : path === "/api/v1/config/diff" ? { changed: false, changedSections: [] } : {};
    await route.fulfill({ json: body, headers: { "X-Containd-Revision": revision() } });
  });
  return updates;
}

test("the security view summarizes zones below target, including zones outside the matrix", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (err) => errors.push(String(err)));
  // Seven zones: the matrix shows six; the seventh is below target too.
  const many = [...zones, { name: "lab", slTarget: 0 }, { name: "cell", slTarget: 0 }, { name: "vendor", slTarget: 1 }];
  await serveSecurity(page, many);
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/security/conduits");
  await page.goto("/topology/");
  await page.getByRole("button", { name: "SECURITY", exact: true }).click();
  await loaded;
  const summary = page.getByRole("status", { name: "Zones below target" });
  await expect(summary).toContainText("3 of 7 zones have unmet SL target checks:");
  await expect(summary).toContainText("OT SL0/2");
  await expect(summary).toContainText("SCADA SL1/3");
  await expect(summary).toContainText("VENDOR SL0/1");
  await expect(page.getByText("Automated checks tag requirements from observed policy; not a standards assessment.", { exact: false })).toBeVisible();
  await expect(page.getByText("Click any conduit cell", { exact: false })).toContainText("IEC 62443 SR requirement checks");
  await expect(page.locator("body")).not.toContainText(/compliance|achieved/i);
  expect(errors).toEqual([]);
});

test("conduit details label requirement check results without claiming a security level", async ({ page }) => {
  await serveSecurity(page, [zones[1], zones[2]], [{
    from: "ot", to: "dmz",
    state: "allow", ids: "none", proto: [], traffic: 0,
    rules: [], gaps: [], mitre: [], defaultDeny: false,
    tlsEnforced: false, protoWhitelist: false, mfaRequired: false,
    auditLogged: true, avEnabled: false,
  }]);
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/security/conduits");
  await page.goto("/topology/");
  await page.getByRole("button", { name: "SECURITY", exact: true }).click();
  await loaded;
  await page.getByText("ALLOW", { exact: true }).click();
  await expect(page.getByText("Checks:0 / SL-T:2", { exact: true })).toBeVisible();
  await expect(page.getByText("CHECK-BASED SL", { exact: true })).toHaveCount(2);
  await expect(page.getByText("Unmet checks for SL-2; check-based SL-0", { exact: true })).toBeVisible();
  await expect(page.getByText("SL-1 target checks pass", { exact: true })).toBeVisible();
  await expect(page.getByText("5 unmet SR checks for target", { exact: true })).toBeVisible();
  await expect(page.getByText("CHECK PASS", { exact: true }).first()).toBeVisible();
  await expect(page.getByText("CHECK FAIL", { exact: true }).first()).toBeVisible();
  await expect(page.getByRole("button", { name: "MARK PASS", exact: true }).first()).toBeVisible();
  await expect(page.getByText("OVERRIDE", { exact: true })).toHaveCount(4);
  await expect(page.locator("body")).not.toContainText(/compliance|achieved/i);
});

test("zones label the computed level as check-based SL", async ({ page }) => {
  await serveSecurity(page, zones);
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/security/conduits");
  await page.goto("/zones/");
  await loaded;
  await expect(page.getByRole("columnheader", { name: "Check-based SL", exact: true })).toBeVisible();
  await expect(page.getByRole("columnheader", { name: "SL-T", exact: true })).toBeVisible();
  await expect(page.locator("body")).not.toContainText(/compliance|achieved|SL-A/i);
});

test("colliding zone slugs keep separate scores, conduits and staging targets", async ({ page }) => {
  const zoneList = [{ name: "OT-1", slTarget: 1 }, { name: "ot_1", slTarget: 1 }];
  const admitted = {
    state: "allow" as const, ids: "full" as const, proto: [], traffic: 0,
    rules: [], gaps: [], mitre: [], defaultDeny: true,
    tlsEnforced: true, protoWhitelist: true, mfaRequired: false,
    auditLogged: true, avEnabled: false,
  };
  const updates = await serveSecurity(page, zoneList, [
    { ...admitted, from: "OT-1", to: "ot_1" },
    { ...admitted, from: "ot_1", to: "OT-1", state: "block", defaultDeny: false, auditLogged: false },
  ]);
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/security/conduits");
  await page.goto("/topology/");
  await page.getByRole("button", { name: "SECURITY", exact: true }).click();
  await loaded;
  const summary = page.getByRole("status", { name: "Zones below target" });
  await expect(summary).toContainText("1 of 2 zones have unmet SL target checks:");
  await expect(summary).toContainText("OT_1 SL0/1");
  await expect(summary).not.toContainText("OT-1 SL");
  await page.getByText("ALLOW", { exact: true }).click();
  await expect(page.getByText("OT-1 → OT_1", { exact: true })).toBeVisible();
  await expect(page.getByText("Checks:2 / SL-T:1", { exact: true })).toBeVisible();
  await expect(page.getByText("Checks:0 / SL-T:1", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Stage OT-1 target SL 2", exact: true }).click();
  await expect.poll(() => updates.length).toBe(1);
  expect(updates[0]).toEqual({ name: "OT-1", body: { slTarget: 2 } });
  await page.getByRole("button", { name: "Stage OT_1 target SL 2", exact: true }).click();
  await expect.poll(() => updates.length).toBe(2);
  expect(updates[1]).toEqual({ name: "ot_1", body: { slTarget: 2 } });

  const zoneScoresLoaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/security/conduits");
  await page.goto("/zones/");
  await zoneScoresLoaded;
  const rowFor = (name: string) => page.getByRole("row").filter({ has: page.getByRole("cell", { name, exact: true }) });
  await expect(rowFor("OT-1").locator('td[data-label="Check-based SL"]')).toHaveText("2");
  await expect(rowFor("ot_1").locator('td[data-label="Check-based SL"]')).toHaveText("—");
});

test("arrow-containing endpoints keep distinct matrix selection and zone scores", async ({ page }) => {
  const zoneList = ["a→b", "a", "b", "b→a"].map((name) => ({ name, slTarget: 1 }));
  const admitted = {
    state: "allow" as const, ids: "full" as const, proto: [], traffic: 0,
    rules: [], gaps: [], mitre: [], defaultDeny: true,
    tlsEnforced: true, protoWhitelist: true, mfaRequired: false,
    auditLogged: true, avEnabled: false,
  };
  // These pairs used to share the same joined key.
  await serveSecurity(page, zoneList, [
    { ...admitted, from: "a→b", to: "a", rules: ["arrow source policy"] },
    { ...admitted, from: "a", to: "b→a", state: "block", auditLogged: false, rules: ["arrow destination policy"] },
  ]);
  const loaded = page.waitForResponse("**/api/v1/security/conduits");
  await page.goto("/topology/");
  await page.getByRole("button", { name: "SECURITY", exact: true }).click();
  await loaded;
  const matrix = page.getByRole("region", { name: "Zone conduit matrix" });
  const details = page.getByRole("region", { name: "Conduit details" });
  await matrix.getByText("ALLOW", { exact: true }).click();
  await expect(details).toContainText("A→B → A");
  await expect(details).toContainText("arrow source policy");
  await expect(details.getByRole("button", { name: "Stage A→B target SL 2", exact: true })).toBeVisible();
  await matrix.getByText("BLOCK", { exact: true }).click();
  await expect(details).toContainText("A → B→A");
  await expect(details).toContainText("arrow destination policy");
  await expect(details).not.toContainText("arrow source policy");
  // Removing an endpoint clears selection without splitting either zone name.
  await page.locator('[class*="zoneChipName"]', { hasText: /^B→A$/ }).locator("..").getByTitle("Remove", { exact: true }).click();
  await expect(details).toContainText("SELECT A CELL");

  const scoresLoaded = page.waitForResponse("**/api/v1/security/conduits");
  await page.goto("/zones/");
  await scoresLoaded;
  const rowFor = (name: string) => page.getByRole("row").filter({ has: page.getByRole("cell", { name, exact: true }) });
  await expect(rowFor("a→b").locator('td[data-label="Check-based SL"]')).toHaveText("2");
  await expect(rowFor("a").locator('td[data-label="Check-based SL"]')).toHaveText("—");
  await expect(rowFor("b").locator('td[data-label="Check-based SL"]')).toHaveText("—");
});
