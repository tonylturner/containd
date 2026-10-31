import { expect, test } from "./fixtures/topology-test";

import { topologyStatus } from "../app/topology/topology-status";
import type { HealthResponse, InstalledRulesetStatus } from "../lib/api";

// The topology status chip shows health's firewall enforcement state, and
// unless it is enforcing, why: the installed ruleset's failed apply or
// degraded schedule planner, else health's reason. It no longer reads
// nominal merely because the topology loaded.

const health = (state: NonNullable<HealthResponse["enforcement"]>["state"], reason = ""): HealthResponse =>
  ({ status: "ok", component: "containd", enforcement: { state, reason } });
const loaded = (status: Partial<InstalledRulesetStatus>) => ({ state: "loaded" as const, status: { installed: true, ...status } });
const failedApply = loaded({ error: "nft: syntax error near zone_ot", failedAt: "2026-10-26T08:00:00Z" });

test("the chip follows health's enforcement state", () => {
  expect(topologyStatus(health("enforcing"), loaded({}))).toEqual({ label: "ENFORCING", tone: "ok" });
  // Enforcing has no reason even while an older fault is still loaded.
  expect(topologyStatus(health("enforcing"), failedApply)).toEqual({ label: "ENFORCING", tone: "ok" });
  expect(topologyStatus(health("disabled", "enforcement is off"), { state: "loading" })).toEqual({ label: "ENFORCEMENT OFF", tone: "unknown", reason: "enforcement is off" });
  expect(topologyStatus(undefined, { state: "loading" })).toEqual({ label: "STATUS UNKNOWN", tone: "unknown", reason: "Health unavailable" });
});

test("a degraded chip takes its reason from the installed ruleset status", () => {
  expect(topologyStatus(health("degraded", "last apply failed"), failedApply)).toEqual({
    label: "DEGRADED", tone: "warn", reason: "Last apply failed: nft: syntax error near zone_ot",
  });
  const planner = loaded({ schedulePlanner: { state: "degraded", reason: "refill failed", lastRefill: "", horizonEnd: "" } });
  expect(topologyStatus(health("degraded"), planner).reason).toBe("Schedule planner degraded: refill failed");
  // Without a ruleset fault, or without the ruleset status, health says why.
  expect(topologyStatus(health("degraded", "schedule planner stalled"), loaded({})).reason).toBe("schedule planner stalled");
  expect(topologyStatus(health("degraded", "schedule planner stalled"), { state: "unavailable", error: "forbidden" }).reason).toBe("schedule planner stalled");
  expect(topologyStatus(health("unavailable"), loaded({ installed: false }))).toEqual({ label: "UNAVAILABLE", tone: "error", reason: "No ruleset in force" });
});

test("the topology chip reads degraded with the failed apply while the topology loads", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (err) => errors.push(String(err)));
  await page.addInitScript(() => {
    localStorage.setItem("containd.auth.token", "test-token");
    localStorage.setItem("containd.auth.role", "view");
  });
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const data: Record<string, unknown> = {
      "/api/v1/auth/me": { id: "viewer", username: "viewer", role: "view" },
      "/api/v1/auth/session": { id: "viewer", username: "viewer", role: "view" },
      "/api/v1/health": health("degraded", "last ruleset apply failed"),
      "/api/v1/dataplane/ruleset/status": failedApply.status,
      "/api/v1/config": { zones: [{ name: "it" }], interfaces: [{ name: "lan1", device: "eth0", zone: "it" }], routing: { gateways: [], routes: [], rules: [] }, firewall: { rules: [] } },
      "/api/v1/config/diff": { changed: false, changedSections: [] },
      "/api/v1/interfaces/state": [],
      "/api/v1/flows": [],
      "/api/v1/events": [],
    };
    await route.fulfill({ json: data[path] ?? {} });
  });
  const statusLoaded = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/dataplane/ruleset/status");
  await page.goto("/topology/");
  await statusLoaded;
  const chip = page.getByRole("status", { name: "Firewall enforcement" });
  await expect(chip).toContainText("DEGRADED");
  await expect(chip).toContainText("Last apply failed: nft: syntax error near zone_ot");
  await expect(page.getByText("ALL NOMINAL")).toHaveCount(0);
  await expect(page.getByText("Logical topology unavailable", { exact: false })).toHaveCount(0);
  expect(errors).toEqual([]);
});
