import { expect, test, type Page } from "@playwright/test";

import { describeICSEvidence } from "../app/events/iec104-evidence";
import type { TelemetryEvent } from "../lib/api";

const session = "0123456789abcdef0123456789abcdef-1";
const types = {
  iec104_data_while_stopped: "IEC 104 data transfer not started",
  iec104_send_sequence: "IEC 104 send sequence anomaly",
  iec104_ack_sequence: "IEC 104 acknowledgement anomaly",
  iec104_test_timeout: "IEC 104 TESTFR confirmation timeout",
};

function event(anomalyType: string): TelemetryEvent {
  return {
    id: "1", flowId: "iec-flow", proto: "ids", kind: "anomaly",
    timestamp: "2026-10-26T12:00:00Z",
    srcIp: "10.0.0.1", dstIp: "10.0.0.2", srcPort: 40000, dstPort: 2404, transport: "tcp",
    attributes: {
      anomaly_type: anomalyType, protocol: "iec104", severity: "medium",
      session_id: session, direction: "request", apci_type: "I",
      send_sequence: 3, expected_send_sequence: 1,
    },
  };
}

async function mockAlert(page: Page, alert: TelemetryEvent) {
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const user = { id: "admin-1", username: "containd", role: "admin" };
    let body: unknown = {};
    if (path.endsWith("/auth/me") || path.endsWith("/auth/session")) body = user;
    else if (path.endsWith("/events")) body = [alert];
    else if (path.endsWith("/system/info")) body = { version: "0.1.35", hostname: "containd" };
    await route.fulfill({ contentType: "application/json", body: JSON.stringify(body) });
  });
}

async function detailFitsViewport(page: Page, headline: string, screenshot: string) {
  const panel = page.getByRole("heading", { name: headline, exact: true }).locator("xpath=../../..");
  const bounds = await panel.boundingBox();
  expect(bounds).not.toBeNull();
  console.log("IEC 104 detail bounds", bounds, "viewport", page.viewportSize());
  await page.screenshot({ path: screenshot, fullPage: true });
  expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(page.viewportSize()!.width);
  expect(bounds!.x).toBeGreaterThanOrEqual(0);
  for (const value of ["10.0.0.1:40000", "10.0.0.2:2404", "TCP", "iec-flow"]) {
    await expect(panel.getByText(value, { exact: true })).toBeInViewport({ ratio: 1 });
  }
  await expect(panel.getByText("Time", { exact: true }).locator("..").locator("span").last()).toBeInViewport({ ratio: 1 });
  return panel;
}

for (const [type, label] of Object.entries(types)) {
  test(`${type} has an observational label and session evidence`, () => {
    const view = describeICSEvidence(event(type));
    expect(view?.headline).toBe(label);
    expect(view?.alert).toBe(true);
    expect(view?.badge).toBe("observation");
    expect(view?.sessionId).toBe(session);
    expect(view?.rows).toContainEqual({ label: "N(S)", value: "3" });
    expect(view?.rows).toContainEqual({ label: "Expected N(S)", value: "1" });
  });
}

test("APCI anomaly appears in Alerts with readable type and session link", async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 1280, height: 960 });
  await mockAlert(page, event("iec104_send_sequence"));
  await page.goto("/alerts/");
  await page.getByRole("cell", { name: "IEC 104 send sequence anomaly", exact: true }).click();
  await expect(page.getByRole("heading", { name: "IEC 104 send sequence anomaly" })).toBeVisible();
  await expect(page.getByText("observation", { exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "Open session events" })).toHaveAttribute(
    "href", `/events/?session=${session}`,
  );
  const panel = await detailFitsViewport(page, "IEC 104 send sequence anomaly", testInfo.outputPath("apci-alert.png"));
  for (const [label, value] of [["APCI", "I"], ["N(S)", "3"], ["Expected N(S)", "1"], ["Direction", "request"]]) {
    await expect(panel.getByText(label, { exact: true }).locator("..").getByText(value, { exact: true })).toBeInViewport({ ratio: 1 });
  }
});

test("existing IEC 104 denial detail fits a 1280px viewport", async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 1280, height: 960 });
  await mockAlert(page, {
    ...event(""), proto: "iec104", kind: "ics.decision",
    attributes: {
      session_id: session, apdu_id: `${session}/c/16`, decision: "deny",
      reason: "rule", action: "DENY", mode: "enforce", ruleId: "deny-rule",
      type_id: 46, ca: 1, ioa: 2001, direction: "request",
    },
  });
  await page.goto("/alerts/");
  await page.getByRole("cell", { name: /deny: type 46/ }).click();
  await expect(page.getByRole("heading", { name: "IEC 104 APDU denied" })).toBeVisible();
  await detailFitsViewport(page, "IEC 104 APDU denied", testInfo.outputPath("iec104-existing-alert.png"));
});
