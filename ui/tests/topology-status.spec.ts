import { expect, test } from "./fixtures/topology-test";

import { topologyStatus } from "../app/topology/topology-status";
import type { HealthResponse } from "../lib/api";
import { observation, openProtection, protectionAPI } from "./fixtures/protection-api";

// The topology status chip shows health's firewall enforcement state, and
// unless it is enforcing, a separate protection observation says what traffic
// is affected. Unversioned ruleset detail cannot be joined to that observation.

const health = (state: NonNullable<HealthResponse["enforcement"]>["state"], reason = ""): HealthResponse =>
  ({ status: "ok", component: "containd", enforcement: { state, reason } });
test("the chip follows health's enforcement state", () => {
  expect(topologyStatus(health("enforcing"), observation())).toEqual({ label: "ENFORCING", tone: "ok" });
  expect(topologyStatus(health("enforcing"), observation({ state: "failed" }))).toEqual({ label: "ENFORCING", tone: "ok" });
  expect(topologyStatus(health("disabled"), observation({ state: "disabled" }))).toEqual({
    label: "ENFORCEMENT OFF", tone: "unknown", reason: "Protection disabled", action: "Enable enforcement to protect traffic.",
  });
  expect(topologyStatus(undefined)).toEqual({ label: "STATUS UNKNOWN", tone: "unknown", reason: "Health unavailable" });
});

test("a non-enforcing chip takes reason and action from protection", () => {
  expect(topologyStatus(health("degraded"), observation({ state: "degraded", retryable: true }))).toEqual({
    label: "DEGRADED", tone: "warn", reason: "Rule-hit logging unavailable",
    action: "Nft policy is enforcing; rule-hit evidence is unavailable. Retry protection, then check status.",
  });
  expect(topologyStatus(health("unavailable")).reason).toBe("Protection unknown");
});

test("the topology chip reads effects without joining old ruleset detail", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (err) => errors.push(String(err)));
  await protectionAPI(page, observation({
    state: "failed", effects: [{ traffic: "Monitor IEC 104", effect: "not_inspected" }],
  }), { role: "view" });
  await openProtection(page, "/topology/");
  const chip = page.getByRole("status", { name: "Firewall enforcement" });
  await expect(chip).toContainText("UNAVAILABLE");
  await expect(chip).toContainText("Inspection unavailable — Monitor IEC 104 is not being inspected by containd");
  await expect(chip).not.toContainText("old uncorrelated ruleset error");
  await expect(page.getByText("ALL NOMINAL")).toHaveCount(0);
  await expect(page.getByText("Logical topology unavailable", { exact: false })).toHaveCount(0);
  expect(errors).toEqual([]);
});
