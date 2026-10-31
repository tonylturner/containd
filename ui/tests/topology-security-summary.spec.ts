import { expect, test } from "./fixtures/topology-test";

import { summarizeTargets, targetSummaryText } from "../app/topology/security-summary";
import { mapZone, SR_DEFS } from "../lib/security-scoring";

// The security view's overview counts every zone below its SL target, not
// only the zones shown in the matrix, scored as the matrix scores them.

// Without conduits a zone has no explicit policy (SR-5.1), so it achieves
// SL 0 unless overrides mark its requirements met.
const metUpTo = (sl: number) => Object.fromEntries(SR_DEFS.filter((sr) => sr.sl <= sl).map((sr) => [sr.id, true]));
const zones = [
  { name: "it", slTarget: 0 },
  { name: "ot", slTarget: 2 },
  { name: "dmz", slTarget: 1, slOverrides: metUpTo(1) },
  { name: "scada", slTarget: 3, slOverrides: metUpTo(1) },
];

test("zones below their target are counted across all zones", () => {
  const summary = summarizeTargets(zones.map(mapZone), {});
  expect(summary).toEqual({
    total: 4,
    below: [
      { id: "ot", name: "OT", sl_a: 0, sl_t: 2 },
      { id: "scada", name: "SCADA", sl_a: 1, sl_t: 3 },
    ],
  });
  expect(targetSummaryText(summary)).toBe("2 of 4 zones below SL target:");
  expect(targetSummaryText(summarizeTargets([zones[0], zones[2]].map(mapZone), {}))).toBe("All 2 zones meet their SL targets.");
  expect(targetSummaryText(summarizeTargets([mapZone(zones[1])], {}))).toBe("1 of 1 zone below SL target:");
  expect(targetSummaryText(summarizeTargets([], {}))).toBe("No zones configured.");
});

test("the security view summarizes zones below target, including zones outside the matrix", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (err) => errors.push(String(err)));
  // Seven zones: the matrix shows six; the seventh is below target too.
  const many = [...zones, { name: "lab", slTarget: 0 }, { name: "cell", slTarget: 0 }, { name: "vendor", slTarget: 1 }];
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const body = path === "/api/v1/auth/me" || path === "/api/v1/auth/session" ? { id: "admin", username: "containd", role: "admin" }
      : path === "/api/v1/zones" ? many
        : path === "/api/v1/security/conduits" ? {}
          : path === "/api/v1/config/diff" ? { changed: false, changedSections: [] } : {};
    await route.fulfill({ json: body });
  });
  const loaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/security/conduits");
  await page.goto("/topology/");
  await page.getByRole("button", { name: "SECURITY", exact: true }).click();
  await loaded;
  const summary = page.getByRole("status", { name: "Zones below target" });
  await expect(summary).toContainText("3 of 7 zones below SL target:");
  await expect(summary).toContainText("OT SL0/2");
  await expect(summary).toContainText("SCADA SL1/3");
  await expect(summary).toContainText("VENDOR SL0/1");
  expect(errors).toEqual([]);
});
