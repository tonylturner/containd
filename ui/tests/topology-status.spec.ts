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
    action: "Firewall rules are active, but rule-match logging is unavailable. Retry protection, then check status.",
  });
  expect(topologyStatus(health("unavailable")).reason).toBe("Protection unknown");
});

test("health-only overrides retain their reason when protection is healthy", () => {
  for (const state of ["degraded", "unavailable", "unknown", "disabled"] as const) {
    expect(topologyStatus(health(state, "schedule horizon exhausted"), observation())).toMatchObject({
      reason: "schedule horizon exhausted", action: "",
    });
  }
});

for (const path of ["/topology/", "/firewall/", "/ics/"]) {
  test(`${path} explains health-only degradation without claiming a protection failure`, async ({ page }) => {
    await protectionAPI(page, observation(), {
      enforcement: "degraded", enforcementReason: "schedule horizon exhausted",
    });
    await openProtection(page, path);
    const indicator = page.getByRole("status", {
      name: path === "/topology/" ? "Firewall enforcement" : "Firewall enforcement degraded: degraded",
      exact: true,
    });
    await expect(indicator).toContainText(path === "/topology/" ? "DEGRADED" : "Firewall enforcement degraded");
    if (path === "/topology/") await expect(indicator).toContainText("schedule horizon exhausted");
    else {
      await expect(indicator).toContainText("Protection needs attention");
      // The health reason is a fault cause, so it is shown without expanding.
      const reason = indicator.locator("..").getByText("schedule horizon exhausted", { exact: true });
      await expect(reason).toBeVisible();
      await expect(reason).toHaveCount(1);
    }
    await expect(indicator).not.toContainText("Protecting");
    await expect(page.getByRole("status", { name: "Traffic protection" })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Retry protection" })).toHaveCount(0);
  });
}

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
